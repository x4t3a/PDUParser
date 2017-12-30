#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <list>
#include <sstream>
#include <vector>

namespace arpa
{
    extern "C"
    {
#       include <arpa/inet.h>
    }
}

namespace
{
    struct PCAPFileHeader
    {
        std::uint32_t magic_number;   // magic number
        std::uint16_t version_major;  // major version number
        std::uint16_t version_minor;  // minor version number
        std::int32_t  thiszone;       // GMT to local correction
        std::uint32_t sigfigs;        // accuracy of timestamps
        std::uint32_t snaplen;        // max length of captured packets, in octets
        std::uint32_t network;        // data link type
    } __attribute__((__packed__));
    
    struct PCAPFrameHeader
    {
        std::uint32_t ts_sec;         // timestamp seconds
        std::uint32_t ts_usec;        // timestamp microseconds
        std::uint32_t incl_len;       // number of octets of packet saved in file
        std::uint32_t orig_len;       // actual length of packet
    } __attribute__((__packed__));

    using Byte = char;
    using Bytes = std::vector<Byte>;
    using IPV4 = Byte[4];
    using Port = std::uint16_t;

    struct PDUFrame
    {
        Bytes payload;
        std::string proto_name{};
        IPV4 ipv4_src_addr;
        IPV4 ipv4_dst_addr;
        Port src_port;
        Port dst_port;
    };

    using PDUFrames = std::list<PDUFrame>;
}

Bytes readFile(const std::string& file_name)
{
    enum class Errors : char
    {
        BAD_FILE,
    };

    std::ifstream file_stream{ file_name, std::ios::binary };
    if (!file_stream)
    {
        throw Errors::BAD_FILE;
    }

    file_stream.unsetf(std::ios::skipws);
    file_stream.seekg(0, std::ios::end);
    std::streampos file_size{ file_stream.tellg() };
    file_stream.seekg(0, std::ios::beg);

    Bytes bytes{};
    bytes.reserve(file_size);
    bytes.insert(std::begin(bytes),
                 std::istream_iterator<Byte>(file_stream),
                 std::istream_iterator<Byte>());
    return bytes;
}

PDUFrame parsePDUFrame(const Byte* data, std::size_t len)
{
    enum PDUTags
    {
        PROT_NAME     = 0x0C,
        IPV4_SRC_ADDR = 0x14,
        IPV4_DST_ADDR = 0x15,
        PORT_TYPE     = 0x18,
        SRC_PORT      = 0x19,
        DST_PORT      = 0x1A,
        ORIG_FRM_NUM  = 0x1E,
        END           = 0x00,
    };
    PDUFrame frame{};
    std::size_t pos{ 0 };
    while (true)
    {
        auto tag     = arpa::ntohs(*(reinterpret_cast<std::uint16_t*>(const_cast<Byte*>(data) + pos)));
        pos += sizeof(std::uint16_t);
        if (tag == END) { break; } // all but the END tag have length

        auto tag_len = arpa::ntohs(*(reinterpret_cast<std::uint16_t*>(const_cast<Byte*>(data) + pos)));
        pos += sizeof(std::uint16_t);

        switch (tag)
        {
            case PROT_NAME:
            {
                constexpr unsigned buf_len{ 64 };
                char proto_name[ buf_len ] = { 0 };
                std::memcpy(reinterpret_cast<void*>(proto_name), data + pos, tag_len);
                frame.proto_name = proto_name;
            }
            break;
            case IPV4_SRC_ADDR:
            {
                std::memcpy(reinterpret_cast<void*>(&frame.ipv4_src_addr), data + pos, tag_len);
            }
            break;
            case IPV4_DST_ADDR:
            {
                std::memcpy(reinterpret_cast<void*>(&frame.ipv4_dst_addr), data + pos, tag_len);
            }
            break;
            case SRC_PORT:
            {
                frame.src_port = arpa::ntohl(*(reinterpret_cast<std::uint32_t*>(const_cast<Byte*>(data) + pos)));
            }
            break;
            case DST_PORT:
            {
                frame.dst_port = arpa::ntohl(*(reinterpret_cast<std::uint32_t*>(const_cast<Byte*>(data) + pos)));
            }
            break;
        }
        pos += tag_len;
    }
    Bytes payload{ data + pos, data + len };
    frame.payload = std::move(payload);
    
    return frame;
}

PDUFrames parsePCAP(const Bytes& bytes)
{
    PDUFrames frames{};
    {
        const auto data = bytes.data();
        //PCAPFileHeader pcap_file_hdr{}; // uncomment if need the file's header 
        //std::memcpy(reinterpret_cast<void*>(&pcap_file_hdr), data, sizeof(PCAPFileHeader));
        for (std::size_t pos = sizeof(PCAPFileHeader), end = bytes.size(); pos < end; )
        {
            PCAPFrameHeader frame_hdr{};
            std::memcpy(reinterpret_cast<void*>(&frame_hdr), data + pos, sizeof(PCAPFrameHeader));
            pos += sizeof(PCAPFrameHeader);
            auto frame = parsePDUFrame(data + pos, frame_hdr.incl_len); 
            frames.push_back(frame);
            pos += frame_hdr.incl_len;
        }
    }
    return frames;
}

std::string IPV42Str(const IPV4& addr)
{ 
    std::stringstream ss{};
    ss << static_cast<int>(static_cast<unsigned char>(addr[0])) << '.'
       << static_cast<int>(static_cast<unsigned char>(addr[1])) << '.'
       << static_cast<int>(static_cast<unsigned char>(addr[2])) << '.'
       << static_cast<int>(static_cast<unsigned char>(addr[3]));
    return ss.str();
}

std::string p(const Bytes& bytes)
{
    std::stringstream ss{};
    for (char ch : bytes)
    {
        ss << ch;
    }
    return ss.str();
}

int main(int argc, char* argv[])
{
    if (argc < 2) { return EXIT_FAILURE; }
    auto bytes = readFile(argv[ 1 ]);
    auto frames = parsePCAP(bytes);
    for (const auto& frame : frames)
    {
        if (frame.proto_name == "http-over-tls" || frame.proto_name == "http")
        {
            std::cout << "frame: " << frame.proto_name
                      << ','       << IPV42Str(frame.ipv4_src_addr) << ':' << frame.src_port
                      << ','       << IPV42Str(frame.ipv4_dst_addr) << ':' << frame.dst_port
                      << ','       << p(frame.payload)
                      << '\n';
        }
    }
}


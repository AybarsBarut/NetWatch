using NetWatch.Core.Capture;

namespace NetWatch.Core.Parsing;

public interface IPacketParser
{
    PacketInfo Parse(long number, CapturedFrame frame);
}

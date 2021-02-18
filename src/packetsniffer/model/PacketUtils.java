package packetsniffer.model;

import org.pcap4j.packet.namednumber.IpNumber;

import java.awt.*;
import java.nio.ByteBuffer;

public final class PacketUtils {
    public static String getIpByHex(String hex) {
        var ipLong = Long.parseLong(hex, 16);
        return String.format("%d.%d.%d.%d", ipLong >> 24,
                ipLong >> 16 & 0x00000000000000FF,
                ipLong >> 8 & 0x00000000000000FF,
                ipLong & 0x00000000000000FF);
    }

    public static String getBits(byte b) {
        return String.format("%8s", Integer.toBinaryString(b & 0xff)).replace(" ", "0");
    }

    public static boolean getBit(byte b, int index) {
        return Integer.parseInt(String.valueOf(getBits(b).charAt(index))) != 0;
    }

    public static int getInt(byte[] bytes) {
        byte[] args = new byte[4];
        for (int i = 0; i < 4 - bytes.length; i++)
            args[i] = 0;
        for (int i = 0; i < bytes.length; i++)
            args[3 - i] = bytes[i];
        return ByteBuffer.wrap(args).getInt();
    }

    public static int id(byte[] rawData) {
        var offset = getEthernetHeader().y;
        return getInt(new byte[]{rawData[offset + 5], rawData[offset + 4]});
    }

    public static int getInt(String bits) {
        if (!bits.contains("1")) {
            return 0;
        }
        bits = bits.substring(bits.indexOf('1'));
        var chars = bits.toCharArray();
        int value = 0;
        int pow = (int) Math.pow(2, bits.length());
        for (var c : chars)
            value += (c - '0') * (pow /= 2);
        return value;
    }

    public static Point getEthernetHeader() {
        return new Point(0, 14);
    }

    public static Point getIPHeader(byte[] rawData) {
        var v = getBits(rawData[14]);
        int version = getInt(v.substring(0, 4));
        int ihl = Math.max(getInt(v.substring(4)), 5);
        if (version == 4) {
            return new Point(14, 34 + (ihl - 5) * 4);
        } else {
            return new Point(14, 40 + 14);
        }
    }

    public static Point getTcpHeader(byte[] rawData) {
        var ip = getIPHeader(rawData);
        return new Point(ip.y, ip.y + 20);
    }

    public static Point getUdpHeader(byte[] rawData) {
        var ip = getIPHeader(rawData);
        return new Point(ip.y, ip.y + 8);
    }

    public static boolean isARP(byte[] rawData) {
        return srcAddress(rawData).equals("0.0.0.0");
    }

    /// Ip analyse
    public static boolean[] flagsOfIpv4(byte[] rawData) {
        var index = getEthernetHeader();
        try {
            return new boolean[] {
                    getBit(rawData[index.y + 6], 0),
                    getBit(rawData[index.y + 6], 1),
                    getBit(rawData[index.y + 6], 2)
            };
        } catch (Exception ex) {
            return new boolean[] {false, false, false};
        }
    }

    public static int protocolNumber(byte[] rawData) {
        return getInt(new byte[] {rawData[getEthernetHeader().y + 9]});
    }

    public static String protocol(byte[] rawData) {
        return IpNumber.getInstance((byte) protocolNumber(rawData)).name();
    }

    public static String byteToHex(byte b) {
        return String.format("%02x", b);
    }

    public static String byteToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x:", b));
        }
        return sb.substring(0, sb.length() - 1);
    }

    public static String srcMacAddress(byte[] rawData) {
        return byteToHex(new byte[] {rawData[6], rawData[7], rawData[8], rawData[9], rawData[10], rawData[11]});
    }

    public static String dstMacAddress(byte[] rawData) {
        return byteToHex(new byte[] {rawData[0], rawData[1], rawData[2], rawData[3], rawData[4], rawData[5]});
    }

    public static String srcAddress(byte[] rawData) {
        var offset = getEthernetHeader().y;
        return Byte.toUnsignedInt(rawData[12+offset]) + "." + Byte.toUnsignedInt(rawData[13+offset]) +
                "." + Byte.toUnsignedInt(rawData[14+offset]) + "." + Byte.toUnsignedInt(rawData[15+offset]);
    }

    public static String dstAddress(byte[] rawData) {
        var offset = getEthernetHeader().y;
        return Byte.toUnsignedInt(rawData[16+offset]) + "." + Byte.toUnsignedInt(rawData[17+offset]) +
                "." + Byte.toUnsignedInt(rawData[18+offset]) + "." + Byte.toUnsignedInt(rawData[19+offset]);
    }

    public static String ttl(byte[] rawData) {
        var offset = getEthernetHeader().y;
        return Integer.toString(Byte.toUnsignedInt(rawData[offset+8]));
    }

    public static int srcPort(byte[] rawData) {
        var offset = getIPHeader(rawData).y;
        try {
            return getInt(new byte[] {rawData[offset+1], rawData[offset]});
        } catch (IndexOutOfBoundsException e) {
            return -1;
        }
    }

    public static int dstPort(byte[] rawData) {
        var offset = getIPHeader(rawData).y;
        try {
            return getInt(new byte[] {rawData[offset+3], rawData[offset+2]});
        } catch (IndexOutOfBoundsException e) {
            return -1;
        }
    }

//    public static void main(String[] args) {
//        new PcapThread(
//                p -> {
//                    var po = getEthernetHeader();
//                    if (dstPort(p) == dstPort(p.getRawData())) {
//                        System.out.println("L");
//                    }
//                }
//        ).start();
//    }

    /////
//    public static boolean[] flagsOfIPv4(Packet p) {
//        var res = new boolean[] {false, false, false};
//        try {
//            var ipv4 = p.get(IpV4Packet.class);
//            res[0] = ipv4.getHeader().getReservedFlag();
//            res[0] = ipv4.get(IpV4Packet.class).getHeader().getDontFragmentFlag();
//            res[0] = ipv4.get(IpV4Packet.class).getHeader().getMoreFragmentFlag();
//        } catch (Exception e) {
//            return res;
//        }
//        return res;
//    }
//
//    public static String protocol(Packet p) {
//        try {
//            return p.get(IpV4Packet.class).getHeader().getProtocol().name();
//        } catch (Exception e) {
//            return "Unknown";
//        }
//    }
//
//    public static int protocolNumber(Packet p) {
//        try {
//            return p.get(IpV4Packet.class).getHeader().getProtocol().value();
//        } catch (Exception e) {
//            return -1;
//        }
//    }
//
//    public static String srcMacAddress(Packet p) {
//        try {
//            return p.get(EthernetPacket.class).getHeader().getSrcAddr().toString();
//        } catch (Exception e) {
//            return "null";
//        }
//    }
//
//    public static String dstMacAddress(Packet p) {
//        try {
//            return p.get(EthernetPacket.class).getHeader().getDstAddr().toString();
//        } catch (Exception e) {
//            return "null";
//        }
//    }
//
//    public static String id(Packet p) {
//        try {
//            return Integer.toString(p.get(IpV4Packet.class).getHeader().getIdentificationAsInt());
//        } catch (Exception e) {
//            return "null";
//        }
//    }
//
//    public static String srcAddress(Packet p) {
//        try {
//            return p.get(IpV4Packet.class).getHeader().getSrcAddr().toString();
//        } catch (Exception e) {
//            return "null";
//        }
//    }
//
//    public static String dstAddress(Packet p) {
//        try {
//            return p.get(IpV4Packet.class).getHeader().getDstAddr().toString();
//        } catch (Exception e) {
//            return "null";
//        }
//    }
//
//    public static String ttl(Packet p) {
//        try {
//            return Integer.toString(p.get(IpV4Packet.class).getHeader().getTtlAsInt());
//        } catch (Exception e) {
//            return "null";
//        }
//    }
//
//    public static int srcPort(Packet p) {
//        try {
//            return p.get(TransportPacket.class).getHeader().getSrcPort().valueAsInt();
//        } catch (Exception e) {
//            return -1;
//        }
//    }
//
//    public static int dstPort(Packet p) {
//        try {
//            return p.get(TransportPacket.class).getHeader().getDstPort().valueAsInt();
//        } catch (Exception e) {
//            return -1;
//        }
//    }
}

package packetsniffer.controller;

import packetsniffer.model.PcapThread;
import packetsniffer.view.WindowFrame;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantLock;

import static packetsniffer.model.DataSet.*;
import static packetsniffer.model.PacketUtils.*;

public class Controller {
    public static final WindowFrame window;
    public static final PcapThread pcapThread;
    private static final ReentrantLock lock;

    static {
        lock = new ReentrantLock();
        System.setErr(new PrintStream(new OutputStream() {
            @Override
            public void write(int b) {}
        }));
    }

    static {
        window = new WindowFrame();
        pcapThread = new PcapThread(
                p -> {
                    var pp = p.getRawData();
                    Object[] row = new Object[12];
                    row[0] = ++totalCount;
                    row[1] = id(pp);
                    row[2] = pp.length;
                    row[3] = srcAddress(pp);
                    row[4] = dstAddress(pp);
                    row[5] = protocol(pp);
                    row[6] = pp.length < 10 ? "" : new String(Arrays.copyOfRange(pp, pp.length - 12, pp.length));
                    row[7] = srcMacAddress(pp);
                    row[8] = dstMacAddress(pp);
                    row[9] = ttl(pp);
                    row[10] = srcPort(pp);
                    row[11] = dstPort(pp);
                    switch (protocolNumber(pp)) {
                        case 1: {
                            icmpCount++;
                            tlpStatPieDS.setValue(protocol(pp), icmpCount);
                            break;
                        }
                        case 2: {
                            igmpCount++;
                            tlpStatPieDS.setValue(protocol(pp), igmpCount);
                            break;
                        }
                        case 6: {
                            tcpCount++;
                            tlpStatPieDS.setValue(protocol(pp), tcpCount);
                            break;
                        }
                        case 17: {
                            udpCount++;
                            tlpStatPieDS.setValue(protocol(pp), udpCount);
                            break;
                        }
                        case 47: {
                            greCount++;
                            tlpStatPieDS.setValue(protocol(pp), greCount);
                            break;
                        }
                        default: {
                            tlpOtherCount++;
                            tlpStatPieDS.setValue("Others", tlpOtherCount);
                        }
                    }
                    if (isARP(pp))
                        arpCount++;
                    totalSize += pp.length;
                    if (maxSize < pp.length)
                        maxSize = pp.length;
                    if (minSize > pp.length && pp.length != 0)
                        minSize = pp.length;

                    var srcD = ipPcapCount.getOrDefault(srcAddress(pp), new int[] {0, 0, 0, 0});
                    var dstD = ipPcapCount.getOrDefault(dstAddress(pp), new int[] {0, 0, 0, 0});
                    ipPcapCount.put(srcAddress(pp), new int[] {srcD[0]+1, srcD[1], srcD[2]+p.length(), srcD[3]});
                    ipPcapCount.put(dstAddress(pp), new int[] {dstD[0], dstD[1]+1, dstD[2], dstD[3]+pp.length});

                    boolean notFind = true;
                    for (var port : new int[] {dstPort(pp), srcPort(pp)})
                        if (notFind)
                            switch (port) {
                                case 80: case 443: case 593: {
                                    httpCount++;
                                    alpStatPieDS.setValue("HTTP", httpCount);
                                    notFind = false;
                                    break;
                                }
                                case 20: case 21: case 989: case 990: {
                                    ftpCount++;
                                    alpStatPieDS.setValue("FTP", ftpCount);
                                    notFind = false;
                                    break;
                                }
                                case 53: case 135: case 853: {
                                    dnsCount++;
                                    alpStatPieDS.setValue("DNS", dnsCount);
                                    notFind = false;
                                    break;
                                }
                                case 25: case 465: case 587: case 3535: case 10024: case 10025: {
                                    smtpCount++;
                                    alpStatPieDS.setValue("SMTP", smtpCount);
                                    notFind = false;
                                    break;
                                }
                                case 110: case 995: {
                                    pop3Count++;
                                    alpStatPieDS.setValue("POP3", pop3Count);
                                    notFind = false;
                                    break;
                                }
                                case 23: case 107: case 992: {
                                    telnetCount++;
                                    alpStatPieDS.setValue("Telnet", telnetCount);
                                    notFind = false;
                                    break;
                                }
                                case 69: {
                                    tftpCount++;
                                    alpStatPieDS.setValue("TFTP", tftpCount);
                                    notFind = false;
                                    break;
                                }
                                case 22: {
                                    sshCount++;
                                    alpStatPieDS.setValue("SSH", sshCount);
                                    notFind = false;
                                    break;
                                }
                            }
                    if (notFind) {
                        alpOtherCount++;
                        alpStatPieDS.setValue("Others", alpOtherCount);
                    }
                    packetsInfo.add(p.toString());

                    var ff=  flagsOfIpv4(pp);
                    flagsDS.setValue(flagsDS.getValue(0, 0).intValue() + (!ff[0] ? 1 : 0), "F", "Reserved");
                    flagsDS.setValue(flagsDS.getValue(0, 1).intValue() + (ff[0] ? 1 : 0), "F", "Don't Reserved");
                    flagsDS.setValue(flagsDS.getValue(0, 2).intValue() + (ff[1] ? 1 : 0), "F", "Fragmented");
                    flagsDS.setValue(flagsDS.getValue(0, 3).intValue() + (!ff[1] ? 1 : 0), "F", "Don't Fragmented");
                    flagsDS.setValue(flagsDS.getValue(0, 4).intValue() + (!ff[2] ? 1 : 0), "F", "More Fragment");
                    flagsDS.setValue(flagsDS.getValue(0, 5).intValue() + (ff[2] ? 1 : 0), "F", "No More Fragment");

                    window.getStatisticLabel().setText(
                            "Arrived: " + totalCount + " packets, totalSize: " + totalSize + " bytes, maxSize: " + maxSize +
                                    " bytes, minSize: " + minSize + " bytes, avgSize: " + (totalSize / Math.max(totalCount, 0)) + " bytes.");
                    window.insertPacket(row);
                    try {
                        var model = (DefaultTableModel) ((JTable) ((JViewport) ((JScrollPane)
                                window.getTabbedPane().getComponentAt(3)).getComponent(0)).getComponent(0)).getModel();
                        model.setRowCount(0);
                        int counter = 0;
                        lock.lock();
                        for (var kv : ipPcapCount.entrySet())
                            try {
                                model.addRow(new Object[] {++counter, kv.getKey(), kv.getValue()[0], kv.getValue()[1], kv.getValue()[2], kv.getValue()[3]});
                            } catch (Exception e) {
                                break;
                            }
                        lock.unlock();
                    } catch (Exception ignore) {}
                }
        );
    }

    private Controller() {
    }
}

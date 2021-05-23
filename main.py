'''
            Coded by FARUK OKSUZ
                                    '''

import pyshark
import time
import matplotlib.pyplot as plt
from math import ceil

protocolList = []
sourcePortList = []
destinationPortList = []
allPacketData = []

def main():

    counter = 0  # aynı kaynaktan gelen reset ve ack bayrağını tutan sayac
    capture = pyshark.FileCapture('output.pcap' , only_summaries = False ) #only_summaries=False ile packet içeriği ayrıntılı olarak görüntüleniyor.
    '''
    Dinamik olarak bilgisayarımıza gelen loopback adapter paketleri üzerinden syn flood detection yapmak istersek bu kod satırları kullanılır. 
    Biz saldırı sonucu elimizde bulunan pcap üzerinden bunu gerçekleştireceğiz.
    capture = pyshark.LiveCapture(interface='wi-fi',only_summaries=False) #wi-fi , eth0
    capture.sniff(packet_count=15) #dinlenecek paket sayısı
    capture.sniff(timeout=50) #ms cinsinden
    '''
    for packet in capture:
            try:
                # Packet Content
                protocol = packet.transport_layer  # TCP , UDP
                sourcePort = packet[protocol].srcport
                destinationPort = packet[protocol].dstport

                sourceAddress = packet.ip.src
                destinationAddress = packet.ip.dst

                protocolList.append(protocol)
                sourcePortList.append(sourcePort)
                destinationPortList.append(destinationPort)

                if sourceAddress == "192.168.1.121": #victim

                    #Flags - Boolean
                    sinFlag = bool(packet.tcp.flags_syn)
                    ackFlag = bool(packet.tcp.flags_ack)
                    resetFlag = bool(packet.tcp.flags_reset)

                    #Half-Open Connection - ( Flags - ack ve reset bayrağı aynı anda 1 olduğu durumda %99 olasılıkta server a bir saldırı söz konusudur. )
                    if ackFlag == True and resetFlag == True:
                        #buraya girince zamanı başlat burda geçen zaman eğer 10 saniyeden büyük ise saldırı var demektir.
                        #saniye = time.localtime().tm_sec #sistem saatindeki saniye(alternatif)
                        timer = ceil(time.perf_counter()) # kronometre sıfırdan başladı.
                        counter += 1 #aynı kaynaktan gelen paket sayısını tutan sayac(reset , ack)
                        if counter > 20 and timer > 10: # aynı kaynaktan gelen 20 den fazla reset ve ack bayrağının kurulu olduğu paket varsa VE bu süre 10 saniyeden fazla ise saldırı var demektir.
                            print("Seni anlayamadım bağlantımı yeniliyorum !!! ( victim : {} ->  attacker : {} )".format(sourceAddress ,destinationAddress ))
                        else:
                            print("Şuanlık bir problem yok !")

                    else:
                        print("Saldırı yok !")

                    allPacketData.append( [sourceAddress,sourcePort,destinationAddress,destinationPort,protocol] ) #paket tam içeriği listeye eklendi.

            except AttributeError as ex:
                pass

    plt.hist(protocolList,color='#ffdab9') #TCP , UDP
    plt.title("Protocols")
    plt.show()

if __name__ == "__main__":
    main()

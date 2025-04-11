from scapy.all import sniff, Ether, IP, TCP, UDP

def packet_handler(packet):
  # checa se o pacote é um quadro Ethernet
  if Ether in packet:
    print("quadro Ethernet: ")
    print(f"Endereço de origem: {packet[Ether].src}, Endereço de destino: {packet[Ether].dst}")
  # checa se o pacote é IP
  if IP in packet:
    print("Pacote IP: ")
    print(f"Endereço IP de origem: {packet[IP].src}, Endereço IP de destino: {packet[IP].dst}")
  # checa se é segmento TCP
  if TCP in packet:
    print("Segmento TCP: ")
    print(f"Port de origem: {packet[TCP].sport}, Port de destino: {packet[TCP].dport}")
  # checa se é datagrama UDP
  if UDP in packet:
    print("Datagrama UDP: ")
    print(f"Port de origem: {packet[UDP].sport}, Port de destino: {packet[UDP].dport}")

def start_sniffer():
  print("Iniciando sniffer de rede...")
  print("Este programa irá capturar e exibir informações detalhadas sobre os pacotes de rede")
  print("Pressione Ctrl+C para parar o sniffer")

  # inicia o sniffer e chama a função packet_handler para capturar cada pacote
  sniff(prn=packet_handler, store=0)

if __name__ == "__main__":
  start_sniffer()

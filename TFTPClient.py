#!/usr/bin/python3
"""
$ tftp ip_address [-p port_mumber] <get|put> filename
"""
import socket
import argparse

# import validators
from struct import pack
import sys

DEFAULT_PORT = 69  # TFTP 기본 포트
BLOCK_SIZE = 512  # TFTP 블록 크기
DEFAULT_TRANSFER_MODE = "octet"  # 전송 모드
TIME_OUT = 0.5  # 소켓 타임아웃
MAX_TRY = 5  # 재시도 횟수

# TFTP opcode
OPCODE = {"RRQ": 1, "WRQ": 2, "DATA": 3, "ACK": 4, "ERROR": 5}
MODE = {"netascii": 1, "octet": 2, "mail": 3}

ERROR_CODE = {
    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user.",
}


def send_wrq(filename, mode):
    """서버에 파일 업로드 요청(WRQ) — 로컬 파일 절대 손상되지 않는 안전 버전"""

    # 로컬 파일을 통째로 읽어서 메모리에 저장 (파일을 수정하지 않음)
    try:
        with open(filename, "rb") as fr:   # 파일을 바이너리 읽기 모드로 열기
            file_data_full = fr.read()     # 전체 파일 내용을 읽어 저장
    except FileNotFoundError:
        print(f"File '{filename}' not found.")  # 파일 없을 경우 오류 출력
        return

    # WRQ(Write Request) 패킷 포맷 구성
    # > = big-endian
    # h = short(2바이트)
    # {len(filename)}s = 파일명 문자열
    # B = 1바이트 null(0)
    # {len(mode)}s = 모드 문자열
    format = f">h{len(filename)}sB{len(mode)}sB"

    # WRQ 패킷 생성: [opcode(2) + filename + 0 + mode + 0]
    wrq_message = pack(
        format, OPCODE["WRQ"], bytes(filename, "utf-8"), 0, bytes(mode, "utf-8"), 0
    )

    # 서버에 WRQ 메시지 전송
    sock.sendto(wrq_message, server_address)
    print(f"=> WRQ message: {wrq_message}")

    block_number = 0  # WRQ 후에는 서버로부터 ACK(0)을 받기 때문에 0으로 초기화

    # -----------------------------------------
    #   WRQ 요청 후 서버 ACK(0) 응답 기다림
    # -----------------------------------------
    while True:
        try:
            data, server_new_socket = sock.recvfrom(516)  # 서버 응답 수신
            opcode = int.from_bytes(data[:2], "big")      # 받은 메시지의 opcode 읽기

            if opcode == OPCODE["ACK"]:         # ACK일 경우
                ack_block = int.from_bytes(data[2:4], "big")
                if ack_block == 0:              # WRQ 승인(ACK(0))
                    break                       # 다음 단계(데이터 전송)로 이동

            elif opcode == OPCODE["ERROR"]:     # ERROR 메시지인 경우
                error_code = int.from_bytes(data[2:4], "big")
                print(f"Error: {ERROR_CODE[error_code]}")
                return                           # 업로드 중단

        except socket.timeout:
            # ACK(0) 못받으면 WRQ 메시지 재전송
            print("Timeout waiting for ACK(0). Resending WRQ...")
            sock.sendto(wrq_message, server_address)

    # -----------------------------------------
    #         데이터 블록 전송 시작
    # -----------------------------------------

    # 파일 전체를 512바이트 청크로 나누었을 때 총 몇 블록인지 계산
    total_blocks = (len(file_data_full) + BLOCK_SIZE - 1) // BLOCK_SIZE

    # 블록 번호는 1부터 시작
    for block_number in range(1, total_blocks + 1):

        # 블록별 데이터 범위 계산
        start = (block_number - 1) * BLOCK_SIZE
        end = start + BLOCK_SIZE
        block_data = file_data_full[start:end]   # 현재 블록 데이터 절단

        # DATA 패킷 구성: [opcode(2) + block_number(2) + 데이터]
        data_message = pack(">hh", OPCODE["DATA"], block_number) + block_data

        # 서버에 DATA 블록 전송
        sock.sendto(data_message, server_new_socket)
        print(f"=> Sent block {block_number}")

        # -----------------------------------------
        #       해당 블록의 ACK 수신 대기
        # -----------------------------------------
        retry = 0
        while True:
            try:
                resp, _ = sock.recvfrom(516)            # ACK 또는 ERROR 수신
                resp_opcode = int.from_bytes(resp[:2], "big")

                if resp_opcode == OPCODE["ACK"]:        # ACK 메시지일 경우
                    ack_block = int.from_bytes(resp[2:4], "big")
                    if ack_block == block_number:       # 해당 블록에 대한 ACK이면
                        break                           # 다음 블록으로 진행

                elif resp_opcode == OPCODE["ERROR"]:    # ERROR 메시지
                    error_code = int.from_bytes(resp[2:4], "big")
                    print(f"Error: {ERROR_CODE[error_code]}")
                    return                               # 업로드 종료

            except socket.timeout:
                # ACK를 못받으면 일정 횟수까지 재전송
                retry += 1
                if retry >= MAX_TRY:
                    print(f"Timeout on block {block_number}. Upload failed.")
                    return

                print(f"Timeout waiting for ACK({block_number}). Retrying...")
                sock.sendto(data_message, server_new_socket)

    # 전체 파일 업로드 완료
    print("Upload complete.")


def send_rrq(filename, mode):
    """서버에 파일 다운로드 요청(RRQ)"""
    format = f">h{len(filename)}sB{len(mode)}sB"  # RRQ 메시지 포맷
    rrq_message = pack(
        format, OPCODE["RRQ"], bytes(filename, "utf-8"), 0, bytes(mode, "utf-8"), 0
    )
    sock.sendto(rrq_message, server_address)  # 서버로 RRQ 메시지 전송
    print(f"=> RRQ message: {rrq_message}")


def send_ack(seq_num, server):
    """서버에 ACK 메시지 전송"""
    format = f">hh"
    ack_message = pack(format, OPCODE["ACK"], seq_num)  # ACK 메시지 포맷
    sock.sendto(ack_message, server)  # 서버로 ACK 메시지 전송
    print(f"\n=> Block number: {seq_num}, Ack message: {ack_message}")
    # print(ack_message)


# parse command line arguments
parser = argparse.ArgumentParser(description="TFTP client program")
parser.add_argument(dest="host", help="Server IP address", type=str)
parser.add_argument(dest="operation", help="get or put a file", type=str)
parser.add_argument(dest="filename", help="name of file to transfer", type=str)
parser.add_argument("-p", "--port", dest="port", type=int)
args = parser.parse_args()

"""
if validators.domain(args.host):
    serber_ip = gethostbyname(args.host)
else
    server_ip = args.host
"""

# 서버 주소 설정
server_ip = args.host
if args.port == None:
    server_port = DEFAULT_PORT
else:
    server_port = args.port

server_address = (server_ip, server_port)

# UDP 소켓 생성
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(TIME_OUT)

mode = DEFAULT_TRANSFER_MODE
operation = args.operation.lower()
filename = args.filename


if operation == "get":
    send_rrq(filename, mode)
    # 다운로드 루프
    file = open(filename, "wb")
    expected_block = 1  # 기대하는 블록 번호 초기화
    last_acked = 0  # 마지막으로 ACK 보낸 블록 번호 초기화
    retry_count = 0 # timeout 발생 횟수

    while True:
        try:
            data, server_new_socket = sock.recvfrom(516)  # 최대 516바이트 수신
        except socket.timeout:
            retry_count += 1

            # 첫 블록(1번 블록)을 전혀 받지 못한 상태에서 timeout → 즉시 종료
            if expected_block == 1:
                print("Timeout before receiving first block. Exiting.")
                sys.exit()

            # 첫 블록 이후 timeout → 재시도 횟수 초과 검사
            if retry_count > MAX_TRY:
                print("Max retry exceeded. Exiting.")
                sys.exit()

            # 재전송: 마지막 ACK 다시 보내기
            print("Timeout waiting for data...")
            send_ack(
                last_acked, server_new_socket
            )  # 마지막으로 ACK 보낸 블록 번호 재전송
            continue

        opcode = int.from_bytes(data[:2], "big")  # 수신한 패킷의 opcode 확인

        if opcode == OPCODE["DATA"]:  # 데이터 패킷 처리
            block_num = int.from_bytes(data[2:4], "big")  # 데이터 블록 번호 추출
            file_data = data[4:]  # 실제 파일 데이터 추출
            if block_num == expected_block:  # 기대하는 블록인 경우
                file.write(file_data)
                send_ack(block_num, server_new_socket)  # ACK 전송
                last_acked = block_num  # 마지막으로 ACK 보낸 블록 번호 업데이트
                expected_block += 1
            else:
                send_ack(
                    last_acked, server_new_socket
                )  # 예상 블록 번호가 아니면 마지막으로 ACK 보낸 블록 번호 재전송

            if len(file_data) < BLOCK_SIZE:  # 마지막 블록인 경우
                print("Download complete")
                file.close()
                break

        elif opcode == OPCODE["ERROR"]:
            code = int.from_bytes(data[2:4], "big")  # 오류 코드 추출
            print(
                f"Server Error: {ERROR_CODE.get(code, 'Unknown')}"
            )  # 서버 오류 메시지 출력
            file.close()
            break

elif operation == "put":
    send_wrq(filename, mode)  # 서버에 파일 업로드 요청(WRQ) 전송

else:
    print("Invalid operation. Use 'get' or 'put'.")
    sys.exit()



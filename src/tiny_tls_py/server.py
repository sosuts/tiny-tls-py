import socketserver

from rich.console import Console
from rich.pretty import Pretty

from tiny_tls_py.models.tls_record import TlsRecord


class ServerConfig:
    IP = "0.0.0.0"
    PORT = 10003
    BUFFER_SIZE = 1024


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print("クライアントが接続しました。")
        while True:
            try:
                data = self.request.recv(ServerConfig.BUFFER_SIZE)
            except Exception as e:
                print(f"エラー: {e}")
            if not data:
                print("クライアントが切断しました。")
                break
            print(f"クライアントからのメッセージ: {data.hex()}")
            tls_records: list[TlsRecord] = []
            offset = 0
            while offset < len(data):
                if offset + 5 > len(data):
                    raise ValueError("不完全なTLSRecordヘッダーを検出しました。")
                length = int.from_bytes(data[offset + 3 : offset + 5], "big")
                record_end = offset + 5 + length
                if record_end > len(data):
                    raise ValueError("不完全なTLSRecordを検出しました。")
                record_data = data[offset:record_end]
                tls_record = TlsRecord.from_bytes(record_data)
                tls_records.append(tls_record)
                offset = record_end

            console = Console()
            console.print(
                "受信したTLSレコード:",
                Pretty(tls_records, expand_all=True, indent_size=2, indent_guides=True),
            )


if __name__ == "__main__":
    with socketserver.TCPServer(
        (ServerConfig.IP, ServerConfig.PORT), TCPHandler
    ) as server:
        print(f"サーバーがポート{ServerConfig.PORT}で起動しました。")
        server.serve_forever()

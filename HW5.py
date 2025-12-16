import asyncio
import base64
import hashlib
import json
import struct

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

CLIENTS = {}
WRITERS_TO_ID = {}


async def handshake(reader, writer):
    headers = {}
    try:
        while True:
            line = await reader.readline()
            line = line.decode().strip()
            if not line:
                break
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key] = value
    except Exception:
        writer.close()
        return False

    if "Sec-WebSocket-Key" not in headers:
        writer.close()
        return False

    key = headers["Sec-WebSocket-Key"]
    accept_key = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key}\r\n\r\n"
    )
    writer.write(response.encode())
    await writer.drain()
    return True


def create_frame(message):
    data = message.encode('utf-8')
    length = len(data)
    frame = bytearray([0x81])

    if length <= 125:
        frame.append(length)
    elif length <= 65535:
        frame.append(126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack("!Q", length))

    frame.extend(data)
    return frame


async def read_frame(reader):
    try:
        header = await reader.readexactly(2)
        b1, b2 = header[0], header[1]

        opcode = b1 & 0x0F
        is_masked = b2 & 0x80
        payload_len = b2 & 0x7F

        if opcode == 8:
            return None

        if payload_len == 126:
            data = await reader.readexactly(2)
            payload_len = struct.unpack("!H", data)[0]
        elif payload_len == 127:
            data = await reader.readexactly(8)
            payload_len = struct.unpack("!Q", data)[0]

        mask_key = None
        if is_masked:
            mask_key = await reader.readexactly(4)

        payload = await reader.readexactly(payload_len)

        if is_masked:
            decoded = bytearray(len(payload))
            for i in range(len(payload)):
                decoded[i] = payload[i] ^ mask_key[i % 4]
            payload = decoded

        return payload.decode('utf-8')

    except (asyncio.IncompleteReadError, ConnectionResetError):
        return None
    except Exception:
        return None


async def send_msg(writer, message_dict):
    try:
        if writer.is_closing():
            return
        json_str = json.dumps(message_dict)
        frame = create_frame(json_str)
        writer.write(frame)
        await writer.drain()
    except Exception:
        pass


async def broadcast(message_dict, exclude_id=None):
    tasks = []
    json_str = json.dumps(message_dict)
    frame = create_frame(json_str)

    for uid, writer in list(CLIENTS.items()):
        if uid != exclude_id:
            try:
                if not writer.is_closing():
                    writer.write(frame)
                    tasks.append(writer.drain())
            except Exception:
                pass

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def client_handler(reader, writer):
    if not await handshake(reader, writer):
        return

    user_id = None

    try:
        while True:
            message = await read_frame(reader)
            if message is None:
                break

            if message == 'ping':
                writer.write(create_frame('pong'))
                await writer.drain()
                continue

            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                continue

            mtype = data.get('mtype')

            if mtype == 'INIT':
                user_id = data.get('id')
                CLIENTS[user_id] = writer
                WRITERS_TO_ID[writer] = user_id

                await broadcast({'mtype': 'USER_ENTER', 'id': user_id}, exclude_id=user_id)

            elif mtype == 'TEXT':
                sender_id = data.get('id')
                target_id = data.get('to')
                text_content = data.get('text')

                if not user_id and sender_id:
                    user_id = sender_id
                    WRITERS_TO_ID[writer] = user_id
                    CLIENTS[user_id] = writer

                if target_id:
                    if target_id in CLIENTS:
                        dm_msg = {
                            'mtype': 'DM',
                            'id': sender_id,
                            'text': text_content
                        }
                        await send_msg(CLIENTS[target_id], dm_msg)
                else:
                    public_msg = {
                        'mtype': 'MSG',
                        'id': sender_id,
                        'text': text_content
                    }
                    await broadcast(public_msg, exclude_id=sender_id)

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        if writer in WRITERS_TO_ID:
            uid = WRITERS_TO_ID[writer]
            del WRITERS_TO_ID[writer]

            if uid in CLIENTS and CLIENTS[uid] == writer:
                del CLIENTS[uid]
                await broadcast({'mtype': 'USER_LEAVE', 'id': uid})

        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass


async def main():
    server = await asyncio.start_server(
        client_handler, 'localhost', 8080
    )
    print("Сервер запущен на ws://localhost:8080")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
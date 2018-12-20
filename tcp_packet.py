tcp_bodies = dict()
packet_id_map = dict()          # expected_seq -> id

packet_id_struct = dict()       # Access all segment by one packet id

class tcpPacket:
    def __init__(self, packet_id, buf, header):
        self.packet_id = packet_id
        self.header = header
        self.body_buf = buf[header.header_length:]
        # print(header.sequence_number, self.header.header_length, len(self.body_buf))
        if len(self.body_buf) != 0:
            if header.sequence_number in packet_id_map:
                bodies_id = packet_id_map[header.sequence_number]
                data = tcp_bodies.pop(bodies_id)
                expected_next_seq = header.sequence_number + len(self.body_buf)
                data['expected_next_seq'] = expected_next_seq
                data['data'] = data['data'] + self.body_buf

                packet_id_struct[data['packet_ids'][0]].append(packet_id)
                packet_id_struct[packet_id] = packet_id_struct[data['packet_ids'][0]]

                tcp_bodies[packet_id] = data
                packet_id_map.pop(header.sequence_number)
                packet_id_map[expected_next_seq] = packet_id

            else:
                packet_id_struct[packet_id] = [packet_id]
                expected_next_seq = header.sequence_number + len(self.body_buf)
                packet_id_map[expected_next_seq] = packet_id
                tcp_bodies[packet_id] = {
                    'expected_next_seq': expected_next_seq,
                    'data': self.body_buf,
                    'packet_ids': [packet_id]
                }
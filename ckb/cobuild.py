import ckb.molecule


class Action:
    def __init__(self, script_info_hash: bytearray, script_hash: bytearray, data: bytearray):
        assert len(script_info_hash) == 32
        assert len(script_hash) == 32
        self.script_info_hash = script_info_hash
        self.script_hash = script_hash
        self.data = data

    @staticmethod
    def molecule_read(data: bytearray):
        result = ckb.molecule.decode_dynvec(data)
        return Action(
            ckb.molecule.Byte32.molecule_read(result[0]),
            ckb.molecule.Byte32.molecule_read(result[1]),
            ckb.molecule.Bytes.molecule_read(result[2]),
        )

    def molecule(self):
        return ckb.molecule.encode_dynvec([
            ckb.molecule.Byte32(self.script_info_hash).molecule(),
            ckb.molecule.Byte32(self.script_hash).molecule(),
            ckb.molecule.Bytes(self.data).molecule()
        ])


class Message:
    def __init__(self, actions: list[Action]):
        self.actions = actions

    @staticmethod
    def molecule_read(data: bytearray):
        result = ckb.molecule.decode_dynvec(data)
        return Message(
            [Action.molecule_read(e) for e in ckb.molecule.decode_dynvec(result[0])],
        )

    def molecule(self):
        return ckb.molecule.encode_dynvec([
            ckb.molecule.encode_dynvec([e.molecule() for e in self.actions]),
        ])


class SighashAll:
    def __init__(self, message: Message, seal: bytearray):
        self.message = message
        self.seal = seal

    @staticmethod
    def molecule_read(data: bytearray):
        result = ckb.molecule.decode_dynvec(data)
        return SighashAll(
            Message.molecule_read(result[0]),
            ckb.molecule.Bytes.molecule_read(result[1]),
        )

    def molecule(self):
        return ckb.molecule.encode_dynvec([
            self.message.molecule(),
            ckb.molecule.Bytes(self.seal).molecule(),
        ])


class SighashAllOnly:
    def __init__(self, seal: bytearray):
        self.seal = seal

    @staticmethod
    def molecule_read(data: bytearray):
        result = ckb.molecule.decode_dynvec(data)
        return SighashAll(
            ckb.molecule.Bytes.molecule_read(result[1]),
        )

    def molecule(self):
        return ckb.molecule.encode_dynvec([
            ckb.molecule.Bytes(self.seal).molecule(),
        ])


# table ScriptInfo {
#     // The dapp name and domain the script belongs to
#     name: String,
#     url: String,

#     // Script info.
#     // schema: script action schema
#     // message_type: the entry action type used in WitnessLayout
#     script_hash: Byte32,
#     schema: String,
#     message_type: String,
# }

# vector ScriptInfoVec <ScriptInfo>;

# table ResolvedInputs {
# 		outputs: CellOutputVec,
# 		outputs_data: BytesVec,
# }

# table BuildingPacketV1 {
#     message: Message,
#     payload: Transaction,
# 	  resolved_inputs: ResolvedInputs,
#     change_output: Uint32Opt,
#     script_infos: ScriptInfoVec,
#     lock_actions: ActionVec,
# }

# union BuildingPacket {
#     BuildingPacketV1,
# }

# table SealPair {
#     script_hash: Byte32,
#     seal: Bytes,
# }
# vector SealPairVec <SealPair>;

# table OtxStart {
#     start_input_cell: Uint32,
#     start_output_cell: Uint32,
#     start_cell_deps: Uint32,
#     start_header_deps: Uint32,
# }

# table Otx {
#     input_cells: Uint32,
#     output_cells: Uint32,
#     cell_deps: Uint32,
#     header_deps: Uint32,
#     message: Message,
#     seals: SealPairVec,
# }

# Packet Definitions for Minecraft Protocol (Approx 1.9.4 / Ver 110)
# Based on observed IDs: JoinGame=0x23.

PACKET_NAMES = {
    "HANDSHAKE": {
        "C->S": {
            0x00: "Handshake"
        }
    },
    "STATUS": {
        "C->S": {
            0x00: "Request",
            0x01: "Ping"
        },
        "S->C": {
            0x00: "Response",
            0x01: "Pong"
        }
    },
    "LOGIN": {
        "C->S": {
            0x00: "Login Start",
            0x01: "Encryption Response"
        },
        "S->C": {
            0x00: "Disconnect",
            0x01: "Encryption Request",
            0x02: "Login Success",
            0x03: "Set Compression"
        }
    },
    "PLAY": {
        "C->S": {
            0x00: "Teleport Confirm",
            0x01: "Tab Complete",
            0x02: "Chat Message",
            0x03: "Client Status",
            0x04: "Client Settings",
            0x05: "Confirm Transaction",
            0x06: "Enchant Item",
            0x07: "Click Window",
            0x08: "Close Window",
            0x09: "Plugin Message",
            0x0A: "Use Entity",
            0x0B: "Keep Alive",
            0x0C: "Player Position",
            0x0D: "Player Position And Look",
            0x0E: "Player Look",
            0x0F: "Player",
            0x10: "Vehicle Move",
            0x11: "Steer Boat",
            0x12: "Player Abilities",
            0x13: "Player Digging",
            0x14: "Entity Action",
            0x15: "Steer Vehicle",
            0x16: "Resource Pack Status",
            0x17: "Held Item Change",
            0x18: "Creative Inventory Action",
            0x19: "Update Sign",
            0x1A: "Animation",
            0x1B: "Spectate",
            0x1C: "Player Block Placement",
            0x1D: "Use Item"
        },
        "S->C": {
            0x00: "Spawn Object",
            0x01: "Spawn Experience Orb",
            0x02: "Spawn Global Entity",
            0x03: "Spawn Mob",
            0x04: "Spawn Painting",
            0x05: "Spawn Player",
            0x06: "Animation",
            0x07: "Statistics",
            0x08: "Block Break Animation",
            0x09: "Update Block Entity",
            0x0A: "Block Action",
            0x0B: "Block Change",
            0x0C: "Boss Bar",
            0x0D: "Server Difficulty",
            0x0E: "Tab Complete",
            0x0F: "Chat Message",
            0x10: "Multi Block Change",
            0x11: "Confirm Transaction",
            0x12: "Close Window",
            0x13: "Open Window",
            0x14: "Window Items",
            0x15: "Window Property",
            0x16: "Set Slot",
            0x17: "Set Cooldown",
            0x18: "Plugin Message",
            0x19: "Named Sound Effect",
            0x1A: "Disconnect",
            0x1B: "Entity Status",
            0x1C: "Explosion",
            0x1D: "Unload Chunk",
            0x1E: "Change Game State",
            0x1F: "Keep Alive",
            0x20: "Chunk Data",
            0x21: "Effect",
            0x22: "Particle",
            0x23: "Join Game",
            0x24: "Map",
            0x25: "Entity Relative Move",
            0x26: "Entity Look And Relative Move",
            0x27: "Entity Look",
            0x28: "Entity",
            0x29: "Vehicle Move",
            0x2A: "Open Sign Editor",
            0x2B: "Player Abilities",
            0x2C: "Combat Event",
            0x2D: "Player ListItem",
            0x2E: "Player Position And Look",
            0x2F: "Use Bed",
            0x30: "Destroy Entities",
            0x31: "Remove Entity Effect",
            0x32: "Resource Pack Send",
            0x33: "Respawn",
            0x34: "Entity Head Look",
            0x35: "World Border",
            0x36: "Camera",
            0x37: "Held Item Change",
            0x38: "Display Scoreboard",
            0x39: "Entity Metadata",
            0x3A: "Attach Entity",
            0x3B: "Entity Velocity",
            0x3C: "Entity Equipment",
            0x3D: "Set Experience",
            0x3E: "Update Health",
            0x3F: "Scoreboard Objective",
            0x40: "Teams",
            0x41: "Update Score",
            0x42: "Spawn Position",
            0x43: "Time Update",
            0x44: "Title",
            0x45: "Update Sign",
            0x46: "Sound Effect",
            0x47: "Player List Header And Footer",
            0x48: "Collect Item",
            0x49: "Entity Teleport",
            0x4A: "Entity Properties",
            0x4B: "Entity Effect"
        }
    }
}

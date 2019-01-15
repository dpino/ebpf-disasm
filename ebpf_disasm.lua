local ffi = require("ffi")

-- Util.

local function hex (val)
   val = tonumber(val) or 0
   return ("0x%x"):format(val)
end

local function trim (str)
   return str:gsub("%s", "")
end

local function set(t)
   local ret = {}
   for _, each in ipairs(t) do
      ret[each] = true
   end
   return ret
end

-- Registers.

local regs = { "r0", "r1", "r2", "r3", "r4", "r5 ", "r6", "r7", "r8", "r9", "r10" }

local function reg_str (num)
   num = assert(tonumber(num), "Invalid register name: "..num)
   assert(num >= 0 and num <= 10, "Invalid register number: "..num)
   return regs[num + 1]
end

-- Opcodes.

local arith64_instr = {
   [0x07] =   function (instr) return ("add64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x0f] =   function (instr) return ("add64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x17] =   function (instr) return ("sub64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x1f] =   function (instr) return ("sub64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x27] =   function (instr) return ("mul64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x2f] =   function (instr) return ("mul64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x37] =   function (instr) return ("div64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x3f] =   function (instr) return ("div64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x47] =   function (instr) return ("or64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x4f] =   function (instr) return ("or64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x57] =   function (instr) return ("and64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x5f] =   function (instr) return ("and64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x67] =   function (instr) return ("lsh64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x6f] =   function (instr) return ("lsh64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x77] =   function (instr) return ("rsh64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x7f] =   function (instr) return ("rsh64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x87] =   function (instr) return ("neg64 %s"):format(reg_str(instr.dst)) end,
   [0x97] =   function (instr) return ("mod64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x9f] =   function (instr) return ("mod64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0xa7] =   function (instr) return ("xor64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0xaf] =   function (instr) return ("xor64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0xb7] =   function (instr) return ("mov64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0xbf] =   function (instr) return ("mov64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0xc7] =   function (instr) return ("arsh64 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0xcf] =   function (instr) return ("arsh64 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
}

local arith32_instr = {
   [0x04] =   function (instr) return ("add32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x0c] =   function (instr) return ("add32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x14] =   function (instr) return ("sub32 %s, 0x%x"):format(eg_str(instr.dst), instr.imm) end,
   [0x1c] =   function (instr) return ("sub32 %s, %s"):format( reg_str(instr.dst), reg_str(instr.src)) end,
   [0x24] =   function (instr) return ("mul32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x2c] =   function (instr) return ("mul32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x34] =   function (instr) return ("div32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x3c] =   function (instr) return ("div32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x44] =   function (instr) return ("or32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x4c] =   function (instr) return ("or32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x54] =   function (instr) return ("and32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x5c] =   function (instr) return ("and32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x64] =   function (instr) return ("lsh32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x6c] =   function (instr) return ("lsh32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x74] =   function (instr) return ("rsh32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x7c] =   function (instr) return ("rsh32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0x84] =   function (instr) return ("neg32 %s"):format(reg_str(instr.dst)) end,
   [0x94] =   function (instr) return ("mod32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0x9c] =   function (instr) return ("mod32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0xa4] =   function (instr) return ("xor32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0xac] =   function (instr) return ("xor32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0xb4] =   function (instr) return ("mov32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0xbc] =   function (instr) return ("mov32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
   [0xc4] =   function (instr) return ("arsh32 %s, 0x%x"):format(reg_str(instr.dst), instr.imm) end,
   [0xcc] =   function (instr) return ("arsh32 %s, %s"):format(reg_str(instr.dst), reg_str(instr.src)) end,
}

local bitwise_instr = {
   [0xd4] = function (instr)
      local imm = instr.imm
      if imm >= 0 and imm < 2^16 - 1 then
         return ("le16 %s"):format(reg_str(instr.dst))
      end
      if imm >= 2^16 and imm <= 2^32 - 1 then
         return ("le32 %s"):format(reg_str(instr.dst))
      end
      if imm >= 2^32 and imm <= 2^64 - 1 then
         return ("le64 %s"):format(reg_str(instr.dst))
      end
      error("Invalid imm value: "..imm)
   end,
   [0xdc] = function (instr)
      local imm = instr.imm
      if imm >= 0 and imm < 2^16 - 1 then
         return ("be16 %s"):format(reg_str(instr.dst))
      end
      if imm >= 2^16 and imm <= 2^32 - 1 then
         return ("be32 %s"):format(reg_str(instr.dst))
      end
      if imm >= 2^32 and imm <= 2^64 - 1 then
         return ("be64 %s"):format(reg_str(instr.dst))
      end
      error("Invalid imm value: "..imm)
   end
}

-- Read wide immediate value from two instructions.
--
-- Result: i1.imm < 32 | i2.imm.
local function read_wide_imm (i1, i2)
   local ret = {}
   local hi, lo = i1.imm, i2.imm
   local t = ffi.new([[
      union {
         struct {
            uint32_t hi;
            uint32_t lo;
         };
         uint64_t uint64;
         uint8_t bytes[8];
      }
   ]])
   t.hi, t.lo = hi, lo
   for i=7,0,-1 do
      table.insert(ret, ("%x"):format(t.bytes[i]))
   end
   return table.concat(ret)
end

local mov_instr = {
   [0x18] =   function (l, pos)
      local i1, i2 = l[pos], l[pos + 1]
      assert(i2.opcode == 0x0)
      local imm = read_wide_imm(i1, i2)
      return ("lddw %s, 0x%s"):format(reg_str(i1.dst), imm)
   end,
   [0x20] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local imm = instr.imm
      return ("ldabsw %s, %s, 0x%x"):format(src, dst, imm)
   end,
   [0x28] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local imm = instr.imm
      return ("ldabsh %s, %s, 0x%x"):format(src, dst, imm)
   end,
   [0x30] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local imm = instr.imm
      return ("ldabsb %s, %s, 0x%x"):format(src, dst, imm)
   end,
   [0x38] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local imm = instr.imm
      return ("ldabsdw %s, %s, 0x%x"):format(src, dst, imm)
   end,
   [0x40] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local imm = instr.imm
      return ("ldindw %s, %s, 0x%x"):format(src, dst, imm)
   end,
   [0x48] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local imm = instr.imm
      return ("ldindh %s, %s, 0x%x"):format(src, dst, imm)
   end,
   [0x50] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local imm = instr.imm
      return ("ldindb %s, %s, 0x%x"):format(src, dst, imm)
   end,
   [0x58] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local imm = instr.imm
      return ("ldinddw %s, %s, 0x%x"):format(src, dst, imm)
   end,
   [0x61] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local off = instr.off
      return ("ldxw %s, [%s+0x%x]"):format(dst, src, off)
   end,
   [0x69] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local off = instr.off
      return ("ldxh %s, [%s+0x%x]"):format(dst, src, off)
   end,
   [0x71] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local off = instr.off
      return ("ldxb %s, [%s+0x%x]"):format(dst, src, off)
   end,
   [0x79] =   function (instr)
      local src, dst = reg_str(instr.src), reg_str(instr.dst)
      local off = instr.off
      return ("ldxdw %s, [%s+0x%x]"):format(dst, src, off)
   end,
   [0x62] =   function (instr)
      local dst = reg_str(instr.dst)
      local off, imm = instr.off, instr.imm
      return ("stw [%s+0x%x], 0x%x"):format(dst, off, imm)
   end,
   [0x6a] =   function (instr)
      local dst = reg_str(instr.dst)
      local off, imm = instr.off, instr.imm
      return ("sth [%s+0x%x], 0x%x"):format(dst, off, imm)
   end,
   [0x72] =   function (instr)
      local dst = reg_str(instr.dst)
      local off, imm = instr.off, instr.imm
      return ("stb [%s+0x%x], 0x%x"):format(dst, off, imm)
   end,
   [0x7a] =   function (instr)
      local dst = reg_str(instr.dst)
      local off, imm = instr.off, instr.imm
      return ("stdw [%s+0x%x], 0x%x"):format(dst, off, imm)
   end,
   [0x63] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("stxw [%s+0x%x], %s"):format(dst, off, src)
   end,
   [0x6b] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("stxh [%s+0x%x], %s"):format(dst, off, src)
   end,
   [0x73] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("stxb [%s+0x%x], %s"):format(dst, off, src)
   end,
   [0x7b] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("stxdw [%s+0x%x], %s"):format(dst, off, src)
    end,
}

local branch_instr = {
   [0x05] =   function (instr)
      return ("ja +0x%x"):format(instr.off)
   end,
   [0x15] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jeq %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0x1d] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jeq %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0x25] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jgt %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0x2d] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jgt %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0x35] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jge %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0x3d] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jge %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0xa5] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jlt %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0xad] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jlt %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0xb5] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jle %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0xbd] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jle %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0x45] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jset %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0x4d] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jset %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0x55] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jne %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0x5d] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jne %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0x65] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jsgt %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0x6d] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jsgt %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0x75] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jsge %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0x7d] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jsge %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0xc5] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jslt %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0xcd] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jslt %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0xd5] =   function (instr)
      local dst = reg_str(instr.dst)
      local imm, off = instr.imm, instr.off
      return ("jsle %s, 0x%x, +0x%x"):format(dst, imm, off)
   end,
   [0xdd] =   function (instr)
      local dst, src = reg_str(instr.dst), reg_str(instr.src)
      local off = instr.off
      return ("jsle %s, %s, +0x%x"):format(dst, src, off)
   end,
   [0x85] =   function (instr)
      return ("call 0x%x"):format(instr.imm)
   end,
   [0x95] =   function (instr)
      return "exit"
   end,
}

-- Wide opcodes.

-- List of opcodes that are bigger than one instruction.
local wide_opcodes = set{0x18}

local function is_wide_opcode (opc)
   return wide_opcodes[opc]
end

local instr_t = ffi.typeof [[
   union {
      struct {
         uint8_t opcode;
         uint8_t dst:4;
         uint8_t src:4;
         uint16_t off;
         uint32_t imm;
      } __attribute__((packed));
      uint64_t uint64;
      uint8_t data[8];
   }
]]
local instr_ptr_t = ffi.typeof("$*", instr_t)

-- Create new instruction from hexcode.
local function instr_from_hex (val)
   local ret = ffi.new(instr_t)
   local i = 0
   for each in val:gmatch("%x%x") do
      ret.data[i] = tonumber(each, 16)
      i = i + 1
   end
   return ret
end

-- Creates an EBPF program out of an hexdump.
local function hexdump_to_prog (text)
   local ret = {}
   for line in text:gmatch("[^\n]+") do
      line = trim(line)
      local i1, i2 = line:sub(1, 16), line:sub(17)
      table.insert(ret, instr_from_hex(i1))
      table.insert(ret, instr_from_hex(i2))
   end
   return ret
end

local function instr_to_string (list, i)
   local instr = list[i]
   local opcode = instr.opcode
   local opcodes = { arith32_instr, arith64_instr, bitwise_instr, branch_instr, mov_instr }
   for _, set in ipairs(opcodes) do
      local fn = set[opcode]
      if fn then
         assert(type(fn) == 'function')
         if is_wide_opcode(instr.opcode) then
            return fn(list, i), 2
         else
            return fn(instr), 1
         end
      end
   end
end

-- Print out eBPF program.
local function dump_ebpf_prog (prog)
   assert(type(prog) == 'table')
   local i = 1
   while (i <= #prog) do
      local output, pos = instr_to_string(prog, i)
      i = i + pos
      print(output)
   end
end

function test_dump (text)
   local prog = hexdump_to_prog(text)
   dump_ebpf_prog(prog)
end

local eBPF_program = [[
  61120400 00000000 61110000 00000000
  bf130000 00000000 07030000 0e000000
  3d320f00 00000000 18010000 72736520
  00000000 4c320a00 7b1af0ff 00000000
  18010000 616e6e6f 00000000 74207061
  7b1ae8ff 00000000 18010000 44656275
  00000000 673a2043 7b1ae0ff 00000000
  bfa10000 00000000 07010000 e0ffffff
  b7020000 18000000 85000000 06000000
  b7000000 02000000 05001700 00000000
  71120c00 00000000 71160d00 00000000
  b7010000 0a000000 6b1af4ff 00000000
  b7010000 30782578 631af0ff 00000000
  18010000 74685f74 00000000 7970653a
  7b1ae8ff 00000000 18010000 44656275
  00000000 673a2065 7b1ae0ff 00000000
  67060000 08000000 4f260000 00000000
  bf630000 00000000 dc030000 10000000
  bfa10000 00000000 07010000 e0ffffff
  b7020000 16000000 85000000 06000000
  b7000000 02000000 15060100 86dd0000
  b7000000 01000000 95000000 00000000
]]

test_dump(eBPF_program)

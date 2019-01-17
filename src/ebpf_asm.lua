#!/usr/bin/env luajit

local ffi = require("ffi")

-- Util.

local function set (t)
   local ret = {}
   for _, each in ipairs(t) do
      ret[each] = true
   end
   return ret
end

local function dump (t)
   for k,v in pairs(t) do
      if tonumber(v) then
         v = ("%x"):format(v)
      end
      print(k, "."..v..".")
   end
end

local function table_equals (t1, t2)
   for k, v in pairs(t1) do
      if v ~= t2[k] then
         io.stderr:write(v.." ~= "..t2[k].."\n")
         return false
      end
   end
   return true
end

local function hex (val)
   return ("%x"):format(val)
end

-- Opcodes.

local opcodes = {
   -- ALU opcodes 64-bit.
   ["add64_imm"]  = {0x07, {'dst', 'imm'}},
   ["add64"]      = {0x0f, {'dst', 'src'}},
   ["sub64_imm"]  = {0x17, {'dst', 'imm'}},
   ["sub64"]      = {0x1f, {'dst', 'src'}},
   ["mul64_imm"]  = {0x27, {'dst', 'imm'}},
   ["mul64"]      = {0x2f, {'dst', 'src'}},
   ["div64_imm"]  = {0x37, {'dst', 'imm'}},
   ["div64"]      = {0x3f, {'dst', 'src'}},
   ["or64_imm"]   = {0x47, {'dst', 'imm'}},
   ["or64"]       = {0x4f, {'dst', 'src'}},
   ["and64_imm"]  = {0x57, {'dst', 'imm'}},
   ["and64"]      = {0x5f, {'dst', 'src'}},
   ["lsh64_imm"]  = {0x67, {'dst', 'imm'}},
   ["lsh64"]      = {0x6f, {'dst', 'src'}},
   ["rsh64_imm"]  = {0x77, {'dst', 'imm'}},
   ["rsh64"]      = {0x7f, {'dst', 'src'}},
   ["neg64"]      = {0x87, {'dst'}},
   ["mod64_imm"]  = {0x97, {'dst', 'imm'}},
   ["mod64"]      = {0x9f, {'dst', 'src'}},
   ["xor64_imm"]  = {0xa7, {'dst', 'imm'}},
   ["xor64"]      = {0xaf, {'dst', 'src'}},
   ["mov64_imm"]  = {0xb7, {'dst', 'imm'}},
   ["mov64"]      = {0xbf, {'dst', 'src'}},
   ["arsh64_imm"] = {0xc7, {'dst', 'imm'}},
   ["arsh64"]     = {0xcf, {'dst', 'src'}},

   -- ALU opcodes 32-bit.
   ["add32_imm"]  = {0x04, {'dst', 'imm'}},
   ["add32"]      = {0x0c, {'dst', 'src'}},
   ["sub32_imm"]  = {0x14, {'dst', 'imm'}},
   ["sub32"]      = {0x1c, {'dst', 'src'}},
   ["mul32_imm"]  = {0x24, {'dst', 'imm'}},
   ["mul32"]      = {0x2c, {'dst', 'src'}},
   ["div32_imm"]  = {0x34, {'dst', 'imm'}},
   ["div32"]      = {0x3c, {'dst', 'src'}},
   ["or32_imm"]   = {0x44, {'dst', 'imm'}},
   ["or32"]       = {0x4c, {'dst', 'src'}},
   ["and32_imm"]  = {0x54, {'dst', 'imm'}},
   ["and32"]      = {0x5c, {'dst', 'src'}},
   ["lsh32_imm"]  = {0x64, {'dst', 'imm'}},
   ["lsh32"]      = {0x6c, {'dst', 'src'}},
   ["rsh32_imm"]  = {0x74, {'dst', 'imm'}},
   ["rsh32"]      = {0x7c, {'dst', 'src'}},
   ["neg32"]      = {0x84, {'dst'}},
   ["mod32_imm"]  = {0x94, {'dst', 'imm'}},
   ["mod32"]      = {0x9c, {'dst', 'src'}},
   ["xor32_imm"]  = {0xa4, {'dst', 'imm'}},
   ["xor32"]      = {0xac, {'dst', 'src'}},
   ["mov32_imm"]  = {0xb4, {'dst', 'imm'}},
   ["mov32"]      = {0xbc, {'dst', 'src'}},
   ["arsh32_imm"] = {0xc4, {'dst', 'imm'}},
   ["arsh32"]     = {0xcc, {'dst', 'src'}},

   -- Byteswap opcodes.
   ["le16"] = {0xd4, {'dst','imm'}},
   ["le32"] = {0xd4, {'dst','imm'}},
   ["le64"] = {0xd4, {'dst','imm'}},
   ["be16"] = {0xdc, {'dst','imm'}},
   ["be32"] = {0xdc, {'dst','imm'}},
   ["be64"] = {0xdc, {'dst','imm'}},

   -- Memory opcodes.
   ["lddw"]    = {0x18, {'dst', 'imm'}},
   ["ldabsw"]  = {0x20, {'src', 'dst', 'imm'}},
   ["ldabsh"]  = {0x28, {'src', 'dst', 'imm'}},
   ["ldabsb"]  = {0x30, {'src', 'dst', 'imm'}},
   ["ldabsdw"] = {0x38, {'src', 'dst', 'imm'}},
   ["ldindw"]  = {0x40, {'src', 'dst', 'imm'}},
   ["ldindh"]  = {0x48, {'src', 'dst', 'imm'}},
   ["ldindb"]  = {0x50, {'src', 'dst', 'imm'}},
   ["ldinddw"] = {0x58, {'src', 'dst', 'imm'}},
   ["ldxw"]    = {0x61, {'dst', '[src+off]'}},
   ["ldxh"]    = {0x69, {'dst', '[src+off]'}},
   ["ldxb"]    = {0x71, {'dst', '[src+off]'}},
   ["ldxdw"]   = {0x79, {'dst', '[src+off]'}},
   ["stw"]     = {0x62, {'[dst+off]', 'imm'}},
   ["sth"]     = {0x6a, {'[dst+off]', 'imm'}},
   ["stb"]     = {0x72, {'[dst+off]', 'imm'}},
   ["stdw"]    = {0x7a, {'[dst+off]', 'imm'}},
   ["stxw"]    = {0x63, {'[dst+off]', 'src'}},
   ["stxh"]    = {0x6b, {'[dst+off]', 'src'}},
   ["stxb"]    = {0x73, {'[dst+off]', 'src'}},
   ["stxdw"]   = {0x7b, {'[dst+off]', 'src'}},

   -- Branch opcodes.
   ["ja"]       = {0x05, {'+off'}},
   ["jeq_imm"]  = {0x15, {'dst', 'imm', '+off'}},
   ["jeq"]      = {0x1d, {'dst', 'src', '+off'}},
   ["jgt_imm"]  = {0x25, {'dst', 'imm', '+off'}},
   ["jgt"]      = {0x2d, {'dst', 'src', '+off'}},
   ["jge_imm"]  = {0x35, {'dst', 'imm', '+off'}},
   ["jge"]      = {0x3d, {'dst', 'src', '+off'}},
   ["jlt_imm"]  = {0xa5, {'dst', 'imm', '+off'}},
   ["jlt"]      = {0xad, {'dst', 'src', '+off'}},
   ["jle_imm"]  = {0xb5, {'dst', 'imm', '+off'}},
   ["jle"]      = {0xbd, {'dst', 'src', '+off'}},
   ["jset_imm"] = {0x45, {'dst', 'imm', '+off'}},
   ["jset"]     = {0x4d, {'dst', 'src', '+off'}},
   ["jne_imm"]  = {0x55, {'dst', 'imm', '+off'}},
   ["jne"]      = {0x5d, {'dst', 'src', '+off'}},
   ["jsgt_imm"] = {0x65, {'dst', 'imm', '+off'}},
   ["jsgt"]     = {0x6d, {'dst', 'src', '+off'}},
   ["jsge_imm"] = {0x75, {'dst', 'imm', '+off'}},
   ["jsge"]     = {0x7d, {'dst', 'src', '+off'}},
   ["jslt_imm"] = {0xc5, {'dst', 'imm', '+off'}},
   ["jslt"]     = {0xcd, {'dst', 'src', '+off'}},
   ["jsle_imm"] = {0xd5, {'dst', 'imm', '+off'}},
   ["jsle"]     = {0xdd, {'dst', 'src', '+off'}},
   ["call"]     = {0x85, {'imm'}},
   ["exit"]     = {0x95},
}

local maybe_imm = set{"jeq", "jgt", "jge", "jlt", "jle", "jset", "jne", "jsgt",
                      "jsge", "jslt", "jsle", "add64", "sub64", "mul64",
                      "div64", "or64", "and64", "lsh64", "rsh64", "mod64",
                      "xor64", "mov64", "arsh64", "add32", "sub32", "mul32",
                      "div32", "or32", "and32", "lsh32", "rsh32", "mod32",
                      "xor32", "mov32", "arsh32"}

local function opcode_lookup (k)
   return opcodes[k]
end

-- Instruction.

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

local function pp (t, opts)
   local cols = opts.cols or 1
   local ret = {}
   local i, l = 0, {}
   local lineno = 0
   for _, each in ipairs(t) do
      table.insert(l, each)
      i = i + 1
      if i == cols then
         local line = table.concat(l, " ")
         if opts.lineno then
            line = ("%.4x"):format(lineno).." "..line
            lineno = lineno + (cols*8)
         end
         table.insert(ret, line)
         i, l = 0, {}
      end
   end
   return table.concat(ret, "\n")
end

local function hexdump (instr)
   local function fn (instr)
      local ret = {}
      for i=0,7 do
         table.insert(ret, ("%.2x"):format(instr.data[i]))
         if i == 3 then
            table.insert(ret, " ")
         end
      end
      return table.concat(ret, "")
   end
   if type(instr) == 'table' then
      local ret = {}
      for i=1,#instr do
         table.insert(ret, fn(instr[i]))
      end
      return pp(ret, {cols=2, lineno=true})
   else
      return fn(instr)
   end
end

-- Registers.

local regs = { "r0", "r1", "r2", "r3", "r4", "r5 ", "r6", "r7", "r8", "r9", "r10" }

local function lookup_reg (name)
   for i, each in ipairs(regs) do
      if name == each then
         return i - 1
      end
   end
end

local prog = [[
   ldxw r2, [r1+0x4]
   ldxw r1, [r1+0x0]
   mov64 r3, r1
   add64 r3, 0xe
   jge r2, r3, +0xf
   lddw r1, 0x0a324c20657372
   stxdw [r10+0xfff0], r1
   lddw r1, 0x617020746f6e6e61
   stxdw [r10+0xffe8], r1
   lddw r1, 0x43203a6775626544
   stxdw [r10+0xffe0], r1
   mov64 r1, r10
   add64 r1, 0xffffffe0
   mov64 r2, 0x18
   call 0x6
   mov64 r0, 0x2
   ja +0x17
   ldxb r2, [r1+0xc]
   ldxb r6, [r1+0xd]
   mov64 r1, 0xa
   stxh [r10+0xfff4], r1
   mov64 r1, 0x78257830
   stxw [r10+0xfff0], r1
   lddw r1, 0x3a657079745f6874
   stxdw [r10+0xffe8], r1
   lddw r1, 0x65203a6775626544
   stxdw [r10+0xffe0], r1
   lsh64 r6, 0x8
   or64 r6, r2
   mov64 r3, r6
   be16 r3
   mov64 r1, r10
   add64 r1, 0xffffffe0
   mov64 r2, 0x16
   call 0x6
   mov64 r0, 0x2
   jeq r6, 0xdd86, +0x1
   mov64 r0, 0x1
   exit
]]

local byteswap_imm = {
   be16 = '16',
   be32 = '32',
   be64 = '64',
   le16 = '16',
   le32 = '32',
   le64 = '64',
}

-- TODO: Create a Parser object that can read a file and parse it.
-- It can emit parsed lines or perhaps transform the parsed lines to
-- the final bytecode, all in one pass.

local function parse_line (l)
   local ret = {}
   local opcode, arg
   local pos = 0
   opcode, pos = l:match("([^%s]+)()", pos)
   table.insert(ret, opcode)
   while true do
      arg, pos = l:match("([^,\n%s]+)()", pos)
      if not arg then break end
      table.insert(ret, arg)
   end
   assert(#ret <= 4, "Too many arguments: "..l)
   -- Adjust byteswap imm value depending on opcode.
   local imm = byteswap_imm[ret[1]]
   if imm then ret[3] = imm end
   return ret
end

local function parse_reg (name)
   local val = lookup_reg(name)
   if not val then
      error("Error parsing register: "..name)
   end
   return val
end

local function parse_number (val)
   return assert(tonumber(val), "Error parsing value: "..val)
end

local function parse_reg_off (str)
   local reg, off = str:match('%[([%w]+)+([%w]+)%]')
   if not reg then
      error("Error parsing string: "..str)
   end
   return parse_reg(reg), parse_number(off)
end

local function is_wide (opcode)
   return opcode == 0x18
end

local function hilo (val)
   assert(type(val) == 'string')
   if val:sub(1,2) == "0x" then
      val = val:sub(3)
   end
   local len = #val
   local lo = tonumber(val:sub(1,len-8), 16)
   local hi = tonumber(val:sub(len-7, len), 16)
   return hi, lo
end

-- Transforms 't' to intermediate representation.
-- @param: 't', a table containing a parsed line, i.e:
--    {'mov64', 'r0', '0x1'}
-- @return intermediate representation table, i.e:
--    {opcode=0xb7, dst=0, imm=1}
--
local function emit_ir (t)
   assert(type(t) == 'table')
   local function fetch_instr (k)
      local t = opcodes[k]
      if not t then return end
      return t[1], t[2] or {}
   end
   local k = t[1]
   if maybe_imm[k] then
      local imm = tonumber(t[3])
      if imm then k = k.."_imm" end
   end
   local opcode, args = fetch_instr(k)
   if not opcode then
      error("Couldn't find opcode: "..t[1])
   end
   table.remove(t, 1)
   assert(#t == #args)

   -- Return table with opcode and argument values.
   local ret = {opcode = opcode}
   for i,name in ipairs(args) do
      if name == 'dst' or name == 'src' then
         ret[name] = parse_reg(t[i])
      elseif name == 'imm' then
         local imm = t[i]
         if is_wide(opcode) then
            ret['hi'], ret['lo'] = hilo(imm)
         else
            ret[name] = parse_number(imm)
         end
      elseif name == '+off' then
         name = name:sub(2)
         ret[name] = parse_number(t[i])
      elseif name == '[src+off]' then
         ret['src'], ret['off'] = parse_reg_off(t[i])
      elseif name == '[dst+off]' then
         ret['dst'], ret['off'] = parse_reg_off(t[i])
      else
         error("Unexpected token: "..name)
      end
   end
   return ret
end

local function emit_instr (t)
   local function new_instr (t)
      local ret = ffi.new(instr_t)
      ret.opcode = t.opcode or 0
      ret.dst = t.dst or 0
      ret.src = t.src or 0
      ret.off = t.off or 0
      ret.imm = t.imm or 0
      return ret
   end
   if is_wide(t.opcode) then
      local hi, lo = assert(t.hi), assert(t.lo)
      local instr1 = new_instr(t)
      instr1.imm = hi
      local instr2 = new_instr({})
      instr2.imm = lo
      return {instr1, instr2}, 2
   else
      return {new_instr(t)}, 1
   end
end

local function test_asm ()
   local l = parse_line("mov64 r0, 0x1")
   assert(table_equals(l, {'mov64', 'r0', '0x1'}))
   local ir = emit_ir(l)
   assert(table_equals(ir, {opcode=0xb7, dst=0, imm=0x1}))
   local instr, n = emit_instr(ir)
   assert(n == 1)
   assert((hexdump(unpack(instr)) == "b7000000 01000000"))
end

local function test_parse_lines ()
   local function test_parse_line (l, t)
      assert(table_equals(parse_line(l), t))
   end
   test_parse_line("mov64 r0, 0x1",               {'mov64', 'r0', '0x1'})
   test_parse_line("ldxw r2, [r1+0x4]",           {'ldxw',  'r2', '[r1+0x4]'})
   test_parse_line("ldxw r1, [r1+0x0]",           {'ldxw',  'r1', '[r1+0x0]'})
   test_parse_line("mov64 r3, r1",                {'mov64', 'r3', 'r1'})
   test_parse_line("add64 r3, 0xe",               {'add64', 'r3', '0xe'})
   test_parse_line("jge r2, r3, +0xf",            {'jge',   'r2', 'r3', '+0xf'})
   test_parse_line("lddw r1, 0x0a324c20657372",   {'lddw',  'r1', '0x0a324c20657372'})
   test_parse_line("stxdw [r10+0xfff0], r1",      {'stxdw', '[r10+0xfff0]', 'r1'})
   test_parse_line("lddw r1, 0x617020746f6e6e61", {'lddw',  'r1', '0x617020746f6e6e61'})
   test_parse_line("stxdw [r10+0xffe8], r1",      {'stxdw', '[r10+0xffe8]', 'r1'})
   test_parse_line("lddw r1, 0x43203a6775626544", {'lddw',  'r1', '0x43203a6775626544'})
   test_parse_line("stxdw [r10+0xffe0], r1",      {'stxdw', '[r10+0xffe0]', 'r1'})
   test_parse_line("mov64 r1, r10",               {'mov64', 'r1', 'r10'})
   test_parse_line("add64 r1, 0xffffffe0",        {'add64', 'r1', '0xffffffe0'})
   test_parse_line("mov64 r2, 0x18",              {'mov64', 'r2', '0x18'})
   test_parse_line("call 0x6",                    {'call',  '0x6'})
   test_parse_line("mov64 r0, 0x2",               {'mov64', 'r0', '0x2'})
   test_parse_line("ja +0x17",                    {'ja',    '+0x17'})
   test_parse_line("ldxb r2, [r1+0xc]",           {'ldxb',  'r2', '[r1+0xc]'})
   test_parse_line("ldxb r6, [r1+0xd]",           {'ldxb',  'r6', '[r1+0xd]'})
   test_parse_line("mov64 r1, 0xa",               {'mov64', 'r1', '0xa'})
   test_parse_line("stxh [r10+0xfff4], r1",       {'stxh',  '[r10+0xfff4]', 'r1'})
   test_parse_line("mov64 r1, 0x78257830",        {'mov64', 'r1', '0x78257830'})
   test_parse_line("stxw [r10+0xfff0], r1",       {'stxw',  '[r10+0xfff0]', 'r1'})
   test_parse_line("lddw r1, 0x3a657079745f6874", {'lddw',  'r1', '0x3a657079745f6874'})
   test_parse_line("stxdw [r10+0xffe8], r1",      {'stxdw', '[r10+0xffe8]', 'r1'})
   test_parse_line("lddw r1, 0x65203a6775626544", {'lddw',  'r1', '0x65203a6775626544'})
   test_parse_line("stxdw [r10+0xffe0], r1",      {'stxdw', '[r10+0xffe0]', 'r1'})
   test_parse_line("lsh64 r6, 0x8",               {'lsh64', 'r6', '0x8'})
   test_parse_line("or64 r6, r2",                 {'or64',  'r6', 'r2'})
   test_parse_line("mov64 r3, r6",                {'mov64', 'r3', 'r6'})
   test_parse_line("be16 r3",                     {'be16',  'r3', '16'})
   test_parse_line("mov64 r1, r10",               {'mov64', 'r1', 'r10'})
   test_parse_line("add64 r1, 0xffffffe0",        {'add64', 'r1', '0xffffffe0'})
   test_parse_line("mov64 r2, 0x16",              {'mov64', 'r2', '0x16'})
   test_parse_line("call 0x6",                    {'call',  '0x6'})
   test_parse_line("mov64 r0, 0x2",               {'mov64', 'r0', '0x2'})
   test_parse_line("jeq r6, 0xdd86, +0x1",        {'jeq',   'r6', '0xdd86', '+0x1'})
   test_parse_line("mov64 r0, 0x1",               {'mov64', 'r0', '0x1'})
   test_parse_line("exit",                        {'exit'})
end

local function compile_program (text)
   local ret = {}
   for l in text:gmatch("[^\n]+") do
      local t = assert(parse_line(l))
      if #t > 0 then
         local ir = assert(emit_ir(t))
         local instr, n = assert(emit_instr(ir))
         for i=1,n do
            table.insert(ret, instr[i])
         end
      end
   end
   return ret
end

local function test_compile_program ()
   local prog = [[
      ldxw r2, [r1+0x4]
      ldxw r1, [r1+0x0]
      mov64 r3, r1
      add64 r3, 0xe
      jge r2, r3, +0xf
      lddw r1, 0x0a324c20657372
      stxdw [r10+0xfff0], r1
      lddw r1, 0x617020746f6e6e61
      stxdw [r10+0xffe8], r1
      lddw r1, 0x43203a6775626544
      stxdw [r10+0xffe0], r1
      mov64 r1, r10
      add64 r1, 0xffffffe0
      mov64 r2, 0x18
      call 0x6
      mov64 r0, 0x2
      ja +0x17
      ldxb r2, [r1+0xc]
      ldxb r6, [r1+0xd]
      mov64 r1, 0xa
      stxh [r10+0xfff4], r1
      mov64 r1, 0x78257830
      stxw [r10+0xfff0], r1
      lddw r1, 0x3a657079745f6874
      stxdw [r10+0xffe8], r1
      lddw r1, 0x65203a6775626544
      stxdw [r10+0xffe0], r1
      lsh64 r6, 0x8
      or64 r6, r2
      mov64 r3, r6
      be16 r3
      mov64 r1, r10
      add64 r1, 0xffffffe0
      mov64 r2, 0x16
      call 0x6
      mov64 r0, 0x2
      jeq r6, 0xdd86, +0x1
      mov64 r0, 0x1
      exit
   ]]

   local expected = [[
0000 61120400 00000000 61110000 00000000
0010 bf130000 00000000 07030000 0e000000
0020 3d320f00 00000000 18010000 72736520
0030 00000000 4c320a00 7b1af0ff 00000000
0040 18010000 616e6e6f 00000000 74207061
0050 7b1ae8ff 00000000 18010000 44656275
0060 00000000 673a2043 7b1ae0ff 00000000
0070 bfa10000 00000000 07010000 e0ffffff
0080 b7020000 18000000 85000000 06000000
0090 b7000000 02000000 05001700 00000000
00a0 71120c00 00000000 71160d00 00000000
00b0 b7010000 0a000000 6b1af4ff 00000000
00c0 b7010000 30782578 631af0ff 00000000
00d0 18010000 74685f74 00000000 7970653a
00e0 7b1ae8ff 00000000 18010000 44656275
00f0 00000000 673a2065 7b1ae0ff 00000000
0100 67060000 08000000 4f260000 00000000
0110 bf630000 00000000 dc030000 10000000
0120 bfa10000 00000000 07010000 e0ffffff
0130 b7020000 16000000 85000000 06000000
0140 b7000000 02000000 15060100 86dd0000
0150 b7000000 01000000 95000000 00000000
   ]]

   local linstr = compile_program(prog)
   local actual = hexdump(linstr)
   print(actual)
end

local function instr_to_hexdump (l)
   local t = parse_line(l)
   local ir = emit_ir(t)
   local instr, n = emit_instr(ir)
   if n == 1 then
      print(hexdump(unpack(instr)))
   else
      print(hexdump(instr))
   end
end

function selftest ()
   test_parse_lines()
   test_asm()
   test_compile_program()
end

function run (args)
   local filein = args[1]
   if not filein then
      print("Usage: ebpf-asm <filein> [<fileout>]")
      os.exit(1)
   end

   local fin = io.open(filein, "rt")
   if not fin then
      print("Could not open file: "..filein)
      os.exit(1)
   end
   local content = fin:read("*all")
   fin:close()
   local prog = compile_program(content)

   local fileout = args[2] or "output.bin"
   local fout = io.open(fileout, "wb")
   for _, instr in ipairs(prog) do
      for i=0,7 do
         fout:write(string.char(instr.data[i]))
      end
   end
   fout:close()
   print(fileout)
end

-- selftest()
run(arg)

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
      print(k, v)
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
   ["le16"] = {0xd4, {'dst'}},
   ["le32"] = {0xd4, {'dst'}},
   ["le64"] = {0xd4, {'dst'}},
   ["be16"] = {0xdc, {'dst'}},
   ["be32"] = {0xdc, {'dst'}},
   ["be64"] = {0xdc, {'dst'}},

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

local maybe_imm = set{"jgt", "jge", "jlt", "jle", "jset", "jne", "jsgt",
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

local function emit_instr (t)
   local instr = ffi.new(instr_t)
   instr.opcode = t.opcode
   instr.dst = t.dst or 0
   instr.src = t.src or 0
   instr.off =   t.off or 0
   instr.imm = t.imm or 0
   return instr
end

local function hexdump (instr)
   local t = {}
   for i=0,7 do
      table.insert(t, ("%.2x"):format(instr.data[i]))
      if i == 3 then
         table.insert(t, " ")
      end
   end
   return table.concat(t, "")
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
      arg, pos = l:match("([^, \n]+)()", pos)
      if not arg then break end
      table.insert(ret, arg)
   end
   assert(#ret <= 4, "Too many arguments: "..l)
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
   local reg, off = str:match('[([%w]+)%+([.]+)]')
   if not reg then
      error("Error parsing string: "..str)
   end
   return parse_reg(reg), parse_number(off)
end

-- Transforms 't' to intermediate representation.
-- @param: 't', a table containing a parsed line, i.e:
--    {'mov64', 'r0', '0x1'}
-- @return intermediate representation table, i.e:
--    {opcode=0xb7, dst=0, imm=1}
--
local function to_ir (t)
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
         ret[name] = parse_number(t[i])
      elseif name == '+off' then
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

local function test_asm ()
   local l = parse_line("mov64 r0, 0x1")
   assert(table_equals(l, {'mov64', 'r0', '0x1'}))
   local ir = to_ir(l)
   assert(table_equals(ir, {opcode=0xb7, dst=0, imm=0x1}))
   local instr = emit_instr(ir)
   assert(hexdump(instr) == "b7000000 01000000")
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
   test_parse_line("be16 r3",                     {'be16',  'r3'})
   test_parse_line("mov64 r1, r10",               {'mov64', 'r1', 'r10'})
   test_parse_line("add64 r1, 0xffffffe0",        {'add64', 'r1', '0xffffffe0'})
   test_parse_line("mov64 r2, 0x16",              {'mov64', 'r2', '0x16'})
   test_parse_line("call 0x6",                    {'call',  '0x6'})
   test_parse_line("mov64 r0, 0x2",               {'mov64', 'r0', '0x2'})
   test_parse_line("jeq r6, 0xdd86, +0x1",        {'jeq',   'r6', '0xdd86', '+0x1'})
   test_parse_line("mov64 r0, 0x1",               {'mov64', 'r0', '0x1'})
   test_parse_line("exit",                        {'exit'})
end

function selftest ()
   test_parse_lines()
   test_asm()
end

selftest()

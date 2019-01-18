#!/usr/bin/env luajit

local ffi = require("ffi")
local bit = require("bit")

local bor, band, bxor = bit.bor, bit.band, bit.bxor
local lshift, rshift = bit.lshift, bit.rshift

local function add64 (regs, dst, imm)
   regs[dst] = regs[dst] + imm
end
local function sub64 (regs, dst, imm)
   regs[dst] = regs[dst] - imm
end
local function mul64 (regs, dst, imm)
   regs[dst] = regs[dst] * imm
end
local function div64 (regs, dst, imm)
   regs[dst] = regs[dst] / imm
end
local function or64 (regs, dst, imm)
   regs[dst] = bor(regs[dst], instr.imm)
end
local function and64 (regs, dst, imm)
   regs[dst] = band(regs[dst], instr.imm)
end
local function lshift64 (regs, dst, imm)
   regs[dst] = lshift(regs[dst], instr.imm)
end
local function rshift64 (regs, dst, imm)
   regs[dst] = rshift(regs[dst], instr.imm)
end
local function neg64 (regs, dst)
   regs[dst] = -regs[dst]
end
local function mod64 (regs, dst, imm)
   regs[dst] = regs[dst] % instr.imm
end
local function xor64 (regs, dst, imm)
   regs[dst] = bxor(regs[dst], instr.imm)
end
local function arsh64 (regs, dst, imm)
   regs[dst] = rshift(regs[dst], instr.imm)
end

local opcodes = {
   [0x07] = function (vm, instr)
      add64(vm.regs, instr.dst, instr.imm)
   end,
   [0x0f] = function (vm, instr)
      add64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0x17] = function (vm, instr)
      sub4(vm.regs, instr.dst, instr.imm)
   end,
   [0x1f] = function (vm, instr)
      sub64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0x27] = function (vm, instr)
      mul64(vm.regs, instr.dst, instr.imm)
   end,
   [0x2f] = function (vm, instr)
      mul64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0x37] = function (vm, instr)
      div64(vm.regs, instr.dst, instr.imm)
   end,
   [0x3f] = function (vm, instr)
      div64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0x47] = function (vm, instr)
      or64(vm.regs, instr.dst, instr.imm)
   end,
   [0x4f] = function (vm, instr)
      or64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0x57] = function (vm, instr)
      and64(vm.regs, instr.dst, instr.imm)
   end,
   [0x5f] = function (vm, instr)
      and64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0x67] = function (vm, instr)
      lshift64(vm.regs, instr.dst, instr.imm)
   end,
   [0x6f] = function (vm, instr)
      lshift64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0x77] = function (vm, instr)
      rshif64(vm.regs, instr.dst, instr.imm)
   end,
   [0x7f] = function (vm, instr)
      rshift64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0x87] = function (vm, instr)
      neg64(vm.regs, instr.dst)
   end,
   [0x97] = function (vm, instr)
      mod64(vm.regs, instr.dst, instr.imm)
   end,
   [0x9f] = function (vm, instr)
      mod64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0xa7] = function (vm, instr)
      xor64(vm.regs, instr.dst, instr.imm)
   end,
   [0xaf] = function (vm, instr)
      xor64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
   [0xb7] = function (vm, instr)
      vm.reg[instr.dst] = instr.imm
   end,
   [0xbf] = function (vm, instr)
      vm.reg[instr.dst] = vm.reg[instr.src]
   end,
   [0xc7] = function (vm, instr)
      arsh64(vm.regs, instr.dst, instr.imm)
   end,
   [0xcf] = function (vm, instr)
      arsh64(vm.regs, instr.dst, vm.regs[instr.src])
   end,
}

VM = {}

function VM.new ()
   local o = {
      regs = ffi.new("uint64_t[?]", 10)
   }
   return setmetatable(o, {__index=VM})
end

local hilo = (function()
   local t = ffi.new[[
      union {
         uint64_t u64;
         struct {
            uint32_t lo;
            uint32_t hi;
         };
      }
   ]]
   return function (u64)
      t.u64 = u64
      return t.hi, t.lo
   end
end)()

local function hex (u64)
   local hi, lo = hilo(u64)
   return hi == 0 and ("%x"):format(lo) or
                      ("%x%x"):format(hi, lo)
end

function VM:dump ()
   local ret = {}
   for i=0,9 do
      local val = self.regs[i]
      table.insert(ret, "r"..i..": "..hex(val))
   end
   print(table.concat(ret, ", "))
end

function VM:exec (instr)
   local fn = opcodes[instr.opcode]
   if not fn then return end
   fn(self, instr)
end

function VM:reg (idx)
   idx = assert(tonumber(idx), "Invalid index: "..idx)
   assert(idx >= 0 and idx < 10, "Invalid index number: "..idx)
   return self.regs[idx+1]
end

function selftest ()
   local vm = VM.new()
   -- add64.
   vm:exec({opcode=0x07, dst=0x1, imm=0xff})
   assert(vm.regs[0x1] == 0xff)
end

selftest()

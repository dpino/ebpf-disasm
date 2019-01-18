#!/usr/bin/env luajit

local ffi = require("ffi")

local function add64 (regs, dst, imm)
	regs[dst] = regs[dst] + imm
end

local opcodes = {
	[0x07] = function (vm, instr)
		add64(vm.regs, instr.dst, instr.imm)
	end
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

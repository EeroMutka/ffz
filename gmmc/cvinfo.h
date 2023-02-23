/////////////////////////////////////////////////////////////////////////////// 
// 
// Copyright (c) 2015 Microsoft Corporation. All rights reserved. 
// 
// This code is licensed under the MIT License (MIT). 
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
// THE SOFTWARE. 
// 
///////////////////////////////////////////////////////////////////////////////

/***    cvinfo.h - Generic CodeView information definitions
 *
 *      Structures, constants, etc. for accessing and interpreting
 *      CodeView information.
 *
 */


/***    The master copy of this file resides in the langapi project.
 *      All Microsoft projects are required to use the master copy without
 *      modification.  Modification of the master version or a copy
 *      without consultation with all parties concerned is extremely
 *      risky.
 *
 */

#ifndef _VC_VER_INC
#include "vcver.h"
#endif

#pragma once

 /////////////////////////////////////////////////////////////////////////////// 
 // 
 // Copyright (c) 2015 Microsoft Corporation. All rights reserved. 
 // 
 // This code is licensed under the MIT License (MIT). 
 // 
 // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 // AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 // OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 // THE SOFTWARE. 
 // 
 ///////////////////////////////////////////////////////////////////////////////

 // cvconst.h - codeview constant definitions
 //-----------------------------------------------------------------
 //
 // Copyright Microsoft Corporation.  All Rights Reserved.
 //
 //---------------------------------------------------------------
#ifndef _CVCONST_H_
#define _CVCONST_H_



//      Enumeration for function call type


typedef enum CV_call_e {
    CV_CALL_NEAR_C = 0x00, // near right to left push, caller pops stack
    CV_CALL_FAR_C = 0x01, // far right to left push, caller pops stack
    CV_CALL_NEAR_PASCAL = 0x02, // near left to right push, callee pops stack
    CV_CALL_FAR_PASCAL = 0x03, // far left to right push, callee pops stack
    CV_CALL_NEAR_FAST = 0x04, // near left to right push with regs, callee pops stack
    CV_CALL_FAR_FAST = 0x05, // far left to right push with regs, callee pops stack
    CV_CALL_SKIPPED = 0x06, // skipped (unused) call index
    CV_CALL_NEAR_STD = 0x07, // near standard call
    CV_CALL_FAR_STD = 0x08, // far standard call
    CV_CALL_NEAR_SYS = 0x09, // near sys call
    CV_CALL_FAR_SYS = 0x0a, // far sys call
    CV_CALL_THISCALL = 0x0b, // this call (this passed in register)
    CV_CALL_MIPSCALL = 0x0c, // Mips call
    CV_CALL_GENERIC = 0x0d, // Generic call sequence
    CV_CALL_ALPHACALL = 0x0e, // Alpha call
    CV_CALL_PPCCALL = 0x0f, // PPC call
    CV_CALL_SHCALL = 0x10, // Hitachi SuperH call
    CV_CALL_ARMCALL = 0x11, // ARM call
    CV_CALL_AM33CALL = 0x12, // AM33 call
    CV_CALL_TRICALL = 0x13, // TriCore Call
    CV_CALL_SH5CALL = 0x14, // Hitachi SuperH-5 call
    CV_CALL_M32RCALL = 0x15, // M32R Call
    CV_CALL_CLRCALL = 0x16, // clr call
    CV_CALL_INLINE = 0x17, // Marker for routines always inlined and thus lacking a convention
    CV_CALL_NEAR_VECTOR = 0x18, // near left to right push with regs, callee pops stack
    CV_CALL_RESERVED = 0x19  // first unused call enumeration

    // Do NOT add any more machine specific conventions.  This is to be used for
    // calling conventions in the source only (e.g. __cdecl, __stdcall).
} CV_call_e;


//      Values for the access protection of class attributes


typedef enum CV_access_e {
    CV_private = 1,
    CV_protected = 2,
    CV_public = 3
} CV_access_e;

typedef enum THUNK_ORDINAL {
    THUNK_ORDINAL_NOTYPE,       // standard thunk
    THUNK_ORDINAL_ADJUSTOR,     // "this" adjustor thunk
    THUNK_ORDINAL_VCALL,        // virtual call thunk
    THUNK_ORDINAL_PCODE,        // pcode thunk
    THUNK_ORDINAL_LOAD,         // thunk which loads the address to jump to
    //  via unknown means...

// trampoline thunk ordinals   - only for use in Trampoline thunk symbols
THUNK_ORDINAL_TRAMP_INCREMENTAL,
THUNK_ORDINAL_TRAMP_BRANCHISLAND,

} THUNK_ORDINAL;


enum CV_SourceChksum_t {
    CHKSUM_TYPE_NONE = 0,        // indicates no checksum is available
    CHKSUM_TYPE_MD5,
    CHKSUM_TYPE_SHA1,
    CHKSUM_TYPE_SHA_256,
};

//
// DIA enums
//

enum SymTagEnum
{
    SymTagNull,
    SymTagExe,
    SymTagCompiland,
    SymTagCompilandDetails,
    SymTagCompilandEnv,
    SymTagFunction,
    SymTagBlock,
    SymTagData,
    SymTagAnnotation,
    SymTagLabel,
    SymTagPublicSymbol,
    SymTagUDT,
    SymTagEnum,
    SymTagFunctionType,
    SymTagPointerType,
    SymTagArrayType,
    SymTagBaseType,
    SymTagTypedef,
    SymTagBaseClass,
    SymTagFriend,
    SymTagFunctionArgType,
    SymTagFuncDebugStart,
    SymTagFuncDebugEnd,
    SymTagUsingNamespace,
    SymTagVTableShape,
    SymTagVTable,
    SymTagCustom,
    SymTagThunk,
    SymTagCustomType,
    SymTagManagedType,
    SymTagDimension,
    SymTagCallSite,
    SymTagInlineSite,
    SymTagBaseInterface,
    SymTagVectorType,
    SymTagMatrixType,
    SymTagHLSLType,
    SymTagCaller,
    SymTagCallee,
    SymTagExport,
    SymTagHeapAllocationSite,
    SymTagCoffGroup,
    SymTagMax
};

enum LocationType
{
    LocIsNull,
    LocIsStatic,
    LocIsTLS,
    LocIsRegRel,
    LocIsThisRel,
    LocIsEnregistered,
    LocIsBitField,
    LocIsSlot,
    LocIsIlRel,
    LocInMetaData,
    LocIsConstant,
    LocTypeMax
};

enum DataKind
{
    DataIsUnknown,
    DataIsLocal,
    DataIsStaticLocal,
    DataIsParam,
    DataIsObjectPtr,
    DataIsFileStatic,
    DataIsGlobal,
    DataIsMember,
    DataIsStaticMember,
    DataIsConstant
};

enum UdtKind
{
    UdtStruct,
    UdtClass,
    UdtUnion,
    UdtInterface
};

enum BasicType
{
    btNoType = 0,
    btVoid = 1,
    btChar = 2,
    btWChar = 3,
    btInt = 6,
    btUInt = 7,
    btFloat = 8,
    btBCD = 9,
    btBool = 10,
    btLong = 13,
    btULong = 14,
    btCurrency = 25,
    btDate = 26,
    btVariant = 27,
    btComplex = 28,
    btBit = 29,
    btBSTR = 30,
    btHresult = 31,
    btChar16 = 32,  // char16_t
    btChar32 = 33,  // char32_t
};


//      enumeration for type modifier values

typedef enum CV_modifier_e {
    // 0x0000 - 0x01ff - Reserved.

    CV_MOD_INVALID = 0x0000,

    // Standard modifiers.

    CV_MOD_CONST = 0x0001,
    CV_MOD_VOLATILE = 0x0002,
    CV_MOD_UNALIGNED = 0x0003,

    // 0x0200 - 0x03ff - HLSL modifiers.

    CV_MOD_HLSL_UNIFORM = 0x0200,
    CV_MOD_HLSL_LINE = 0x0201,
    CV_MOD_HLSL_TRIANGLE = 0x0202,
    CV_MOD_HLSL_LINEADJ = 0x0203,
    CV_MOD_HLSL_TRIANGLEADJ = 0x0204,
    CV_MOD_HLSL_LINEAR = 0x0205,
    CV_MOD_HLSL_CENTROID = 0x0206,
    CV_MOD_HLSL_CONSTINTERP = 0x0207,
    CV_MOD_HLSL_NOPERSPECTIVE = 0x0208,
    CV_MOD_HLSL_SAMPLE = 0x0209,
    CV_MOD_HLSL_CENTER = 0x020a,
    CV_MOD_HLSL_SNORM = 0x020b,
    CV_MOD_HLSL_UNORM = 0x020c,
    CV_MOD_HLSL_PRECISE = 0x020d,
    CV_MOD_HLSL_UAV_GLOBALLY_COHERENT = 0x020e,

    // 0x0400 - 0xffff - Unused.

} CV_modifier_e;


//      built-in type kinds


typedef enum CV_builtin_e {

    // 0x0000 - 0x01ff - Reserved.
    CV_BI_INVALID = 0x0000,

    // 0x0200 - 0x03ff - HLSL types.

    CV_BI_HLSL_INTERFACE_POINTER = 0x0200,
    CV_BI_HLSL_TEXTURE1D = 0x0201,
    CV_BI_HLSL_TEXTURE1D_ARRAY = 0x0202,
    CV_BI_HLSL_TEXTURE2D = 0x0203,
    CV_BI_HLSL_TEXTURE2D_ARRAY = 0x0204,
    CV_BI_HLSL_TEXTURE3D = 0x0205,
    CV_BI_HLSL_TEXTURECUBE = 0x0206,
    CV_BI_HLSL_TEXTURECUBE_ARRAY = 0x0207,
    CV_BI_HLSL_TEXTURE2DMS = 0x0208,
    CV_BI_HLSL_TEXTURE2DMS_ARRAY = 0x0209,
    CV_BI_HLSL_SAMPLER = 0x020a,
    CV_BI_HLSL_SAMPLERCOMPARISON = 0x020b,
    CV_BI_HLSL_BUFFER = 0x020c,
    CV_BI_HLSL_POINTSTREAM = 0x020d,
    CV_BI_HLSL_LINESTREAM = 0x020e,
    CV_BI_HLSL_TRIANGLESTREAM = 0x020f,
    CV_BI_HLSL_INPUTPATCH = 0x0210,
    CV_BI_HLSL_OUTPUTPATCH = 0x0211,
    CV_BI_HLSL_RWTEXTURE1D = 0x0212,
    CV_BI_HLSL_RWTEXTURE1D_ARRAY = 0x0213,
    CV_BI_HLSL_RWTEXTURE2D = 0x0214,
    CV_BI_HLSL_RWTEXTURE2D_ARRAY = 0x0215,
    CV_BI_HLSL_RWTEXTURE3D = 0x0216,
    CV_BI_HLSL_RWBUFFER = 0x0217,
    CV_BI_HLSL_BYTEADDRESS_BUFFER = 0x0218,
    CV_BI_HLSL_RWBYTEADDRESS_BUFFER = 0x0219,
    CV_BI_HLSL_STRUCTURED_BUFFER = 0x021a,
    CV_BI_HLSL_RWSTRUCTURED_BUFFER = 0x021b,
    CV_BI_HLSL_APPEND_STRUCTURED_BUFFER = 0x021c,
    CV_BI_HLSL_CONSUME_STRUCTURED_BUFFER = 0x021d,
    CV_BI_HLSL_MIN8FLOAT = 0x021e,
    CV_BI_HLSL_MIN10FLOAT = 0x021f,
    CV_BI_HLSL_MIN16FLOAT = 0x0220,
    CV_BI_HLSL_MIN12INT = 0x0221,
    CV_BI_HLSL_MIN16INT = 0x0222,
    CV_BI_HLSL_MIN16UINT = 0x0223,

    // 0x0400 - 0xffff - Unused.

} CV_builtin_e;


//  enum describing the compile flag source language


typedef enum CV_CFL_LANG {
    CV_CFL_C = 0x00,
    CV_CFL_CXX = 0x01,
    CV_CFL_FORTRAN = 0x02,
    CV_CFL_MASM = 0x03,
    CV_CFL_PASCAL = 0x04,
    CV_CFL_BASIC = 0x05,
    CV_CFL_COBOL = 0x06,
    CV_CFL_LINK = 0x07,
    CV_CFL_CVTRES = 0x08,
    CV_CFL_CVTPGD = 0x09,
    CV_CFL_CSHARP = 0x0A,  // C#
    CV_CFL_VB = 0x0B,  // Visual Basic
    CV_CFL_ILASM = 0x0C,  // IL (as in CLR) ASM
    CV_CFL_JAVA = 0x0D,
    CV_CFL_JSCRIPT = 0x0E,
    CV_CFL_MSIL = 0x0F,  // Unknown MSIL (LTCG of .NETMODULE)
    CV_CFL_HLSL = 0x10,  // High Level Shader Language
} CV_CFL_LANG;


//  enum describing target processor


typedef enum CV_CPU_TYPE_e {
    CV_CFL_8080 = 0x00,
    CV_CFL_8086 = 0x01,
    CV_CFL_80286 = 0x02,
    CV_CFL_80386 = 0x03,
    CV_CFL_80486 = 0x04,
    CV_CFL_PENTIUM = 0x05,
    CV_CFL_PENTIUMII = 0x06,
    CV_CFL_PENTIUMPRO = CV_CFL_PENTIUMII,
    CV_CFL_PENTIUMIII = 0x07,
    CV_CFL_MIPS = 0x10,
    CV_CFL_MIPSR4000 = CV_CFL_MIPS,  // don't break current code
    CV_CFL_MIPS16 = 0x11,
    CV_CFL_MIPS32 = 0x12,
    CV_CFL_MIPS64 = 0x13,
    CV_CFL_MIPSI = 0x14,
    CV_CFL_MIPSII = 0x15,
    CV_CFL_MIPSIII = 0x16,
    CV_CFL_MIPSIV = 0x17,
    CV_CFL_MIPSV = 0x18,
    CV_CFL_M68000 = 0x20,
    CV_CFL_M68010 = 0x21,
    CV_CFL_M68020 = 0x22,
    CV_CFL_M68030 = 0x23,
    CV_CFL_M68040 = 0x24,
    CV_CFL_ALPHA = 0x30,
    CV_CFL_ALPHA_21064 = 0x30,
    CV_CFL_ALPHA_21164 = 0x31,
    CV_CFL_ALPHA_21164A = 0x32,
    CV_CFL_ALPHA_21264 = 0x33,
    CV_CFL_ALPHA_21364 = 0x34,
    CV_CFL_PPC601 = 0x40,
    CV_CFL_PPC603 = 0x41,
    CV_CFL_PPC604 = 0x42,
    CV_CFL_PPC620 = 0x43,
    CV_CFL_PPCFP = 0x44,
    CV_CFL_PPCBE = 0x45,
    CV_CFL_SH3 = 0x50,
    CV_CFL_SH3E = 0x51,
    CV_CFL_SH3DSP = 0x52,
    CV_CFL_SH4 = 0x53,
    CV_CFL_SHMEDIA = 0x54,
    CV_CFL_ARM3 = 0x60,
    CV_CFL_ARM4 = 0x61,
    CV_CFL_ARM4T = 0x62,
    CV_CFL_ARM5 = 0x63,
    CV_CFL_ARM5T = 0x64,
    CV_CFL_ARM6 = 0x65,
    CV_CFL_ARM_XMAC = 0x66,
    CV_CFL_ARM_WMMX = 0x67,
    CV_CFL_ARM7 = 0x68,
    CV_CFL_OMNI = 0x70,
    CV_CFL_IA64 = 0x80,
    CV_CFL_IA64_1 = 0x80,
    CV_CFL_IA64_2 = 0x81,
    CV_CFL_CEE = 0x90,
    CV_CFL_AM33 = 0xA0,
    CV_CFL_M32R = 0xB0,
    CV_CFL_TRICORE = 0xC0,
    CV_CFL_X64 = 0xD0,
    CV_CFL_AMD64 = CV_CFL_X64,
    CV_CFL_EBC = 0xE0,
    CV_CFL_THUMB = 0xF0,
    CV_CFL_ARMNT = 0xF4,
    CV_CFL_ARM64 = 0xF6,
    CV_CFL_D3D11_SHADER = 0x100,
} CV_CPU_TYPE_e;

typedef enum CV_HREG_e {
    // Register subset shared by all processor types,
    // must not overlap with any of the ranges below, hence the high values

    CV_ALLREG_ERR = 30000,
    CV_ALLREG_TEB = 30001,
    CV_ALLREG_TIMER = 30002,
    CV_ALLREG_EFAD1 = 30003,
    CV_ALLREG_EFAD2 = 30004,
    CV_ALLREG_EFAD3 = 30005,
    CV_ALLREG_VFRAME = 30006,
    CV_ALLREG_HANDLE = 30007,
    CV_ALLREG_PARAMS = 30008,
    CV_ALLREG_LOCALS = 30009,
    CV_ALLREG_TID = 30010,
    CV_ALLREG_ENV = 30011,
    CV_ALLREG_CMDLN = 30012,


    //  Register set for the Intel 80x86 and ix86 processor series
    //  (plus PCODE registers)

    CV_REG_NONE = 0,
    CV_REG_AL = 1,
    CV_REG_CL = 2,
    CV_REG_DL = 3,
    CV_REG_BL = 4,
    CV_REG_AH = 5,
    CV_REG_CH = 6,
    CV_REG_DH = 7,
    CV_REG_BH = 8,
    CV_REG_AX = 9,
    CV_REG_CX = 10,
    CV_REG_DX = 11,
    CV_REG_BX = 12,
    CV_REG_SP = 13,
    CV_REG_BP = 14,
    CV_REG_SI = 15,
    CV_REG_DI = 16,
    CV_REG_EAX = 17,
    CV_REG_ECX = 18,
    CV_REG_EDX = 19,
    CV_REG_EBX = 20,
    CV_REG_ESP = 21,
    CV_REG_EBP = 22,
    CV_REG_ESI = 23,
    CV_REG_EDI = 24,
    CV_REG_ES = 25,
    CV_REG_CS = 26,
    CV_REG_SS = 27,
    CV_REG_DS = 28,
    CV_REG_FS = 29,
    CV_REG_GS = 30,
    CV_REG_IP = 31,
    CV_REG_FLAGS = 32,
    CV_REG_EIP = 33,
    CV_REG_EFLAGS = 34,
    CV_REG_TEMP = 40,          // PCODE Temp
    CV_REG_TEMPH = 41,          // PCODE TempH
    CV_REG_QUOTE = 42,          // PCODE Quote
    CV_REG_PCDR3 = 43,          // PCODE reserved
    CV_REG_PCDR4 = 44,          // PCODE reserved
    CV_REG_PCDR5 = 45,          // PCODE reserved
    CV_REG_PCDR6 = 46,          // PCODE reserved
    CV_REG_PCDR7 = 47,          // PCODE reserved
    CV_REG_CR0 = 80,          // CR0 -- control registers
    CV_REG_CR1 = 81,
    CV_REG_CR2 = 82,
    CV_REG_CR3 = 83,
    CV_REG_CR4 = 84,          // Pentium
    CV_REG_DR0 = 90,          // Debug register
    CV_REG_DR1 = 91,
    CV_REG_DR2 = 92,
    CV_REG_DR3 = 93,
    CV_REG_DR4 = 94,
    CV_REG_DR5 = 95,
    CV_REG_DR6 = 96,
    CV_REG_DR7 = 97,
    CV_REG_GDTR = 110,
    CV_REG_GDTL = 111,
    CV_REG_IDTR = 112,
    CV_REG_IDTL = 113,
    CV_REG_LDTR = 114,
    CV_REG_TR = 115,

    CV_REG_PSEUDO1 = 116,
    CV_REG_PSEUDO2 = 117,
    CV_REG_PSEUDO3 = 118,
    CV_REG_PSEUDO4 = 119,
    CV_REG_PSEUDO5 = 120,
    CV_REG_PSEUDO6 = 121,
    CV_REG_PSEUDO7 = 122,
    CV_REG_PSEUDO8 = 123,
    CV_REG_PSEUDO9 = 124,

    CV_REG_ST0 = 128,
    CV_REG_ST1 = 129,
    CV_REG_ST2 = 130,
    CV_REG_ST3 = 131,
    CV_REG_ST4 = 132,
    CV_REG_ST5 = 133,
    CV_REG_ST6 = 134,
    CV_REG_ST7 = 135,
    CV_REG_CTRL = 136,
    CV_REG_STAT = 137,
    CV_REG_TAG = 138,
    CV_REG_FPIP = 139,
    CV_REG_FPCS = 140,
    CV_REG_FPDO = 141,
    CV_REG_FPDS = 142,
    CV_REG_ISEM = 143,
    CV_REG_FPEIP = 144,
    CV_REG_FPEDO = 145,

    CV_REG_MM0 = 146,
    CV_REG_MM1 = 147,
    CV_REG_MM2 = 148,
    CV_REG_MM3 = 149,
    CV_REG_MM4 = 150,
    CV_REG_MM5 = 151,
    CV_REG_MM6 = 152,
    CV_REG_MM7 = 153,

    CV_REG_XMM0 = 154, // KATMAI registers
    CV_REG_XMM1 = 155,
    CV_REG_XMM2 = 156,
    CV_REG_XMM3 = 157,
    CV_REG_XMM4 = 158,
    CV_REG_XMM5 = 159,
    CV_REG_XMM6 = 160,
    CV_REG_XMM7 = 161,

    CV_REG_XMM00 = 162, // KATMAI sub-registers
    CV_REG_XMM01 = 163,
    CV_REG_XMM02 = 164,
    CV_REG_XMM03 = 165,
    CV_REG_XMM10 = 166,
    CV_REG_XMM11 = 167,
    CV_REG_XMM12 = 168,
    CV_REG_XMM13 = 169,
    CV_REG_XMM20 = 170,
    CV_REG_XMM21 = 171,
    CV_REG_XMM22 = 172,
    CV_REG_XMM23 = 173,
    CV_REG_XMM30 = 174,
    CV_REG_XMM31 = 175,
    CV_REG_XMM32 = 176,
    CV_REG_XMM33 = 177,
    CV_REG_XMM40 = 178,
    CV_REG_XMM41 = 179,
    CV_REG_XMM42 = 180,
    CV_REG_XMM43 = 181,
    CV_REG_XMM50 = 182,
    CV_REG_XMM51 = 183,
    CV_REG_XMM52 = 184,
    CV_REG_XMM53 = 185,
    CV_REG_XMM60 = 186,
    CV_REG_XMM61 = 187,
    CV_REG_XMM62 = 188,
    CV_REG_XMM63 = 189,
    CV_REG_XMM70 = 190,
    CV_REG_XMM71 = 191,
    CV_REG_XMM72 = 192,
    CV_REG_XMM73 = 193,

    CV_REG_XMM0L = 194,
    CV_REG_XMM1L = 195,
    CV_REG_XMM2L = 196,
    CV_REG_XMM3L = 197,
    CV_REG_XMM4L = 198,
    CV_REG_XMM5L = 199,
    CV_REG_XMM6L = 200,
    CV_REG_XMM7L = 201,

    CV_REG_XMM0H = 202,
    CV_REG_XMM1H = 203,
    CV_REG_XMM2H = 204,
    CV_REG_XMM3H = 205,
    CV_REG_XMM4H = 206,
    CV_REG_XMM5H = 207,
    CV_REG_XMM6H = 208,
    CV_REG_XMM7H = 209,

    CV_REG_MXCSR = 211, // XMM status register

    CV_REG_EDXEAX = 212, // EDX:EAX pair

    CV_REG_EMM0L = 220, // XMM sub-registers (WNI integer)
    CV_REG_EMM1L = 221,
    CV_REG_EMM2L = 222,
    CV_REG_EMM3L = 223,
    CV_REG_EMM4L = 224,
    CV_REG_EMM5L = 225,
    CV_REG_EMM6L = 226,
    CV_REG_EMM7L = 227,

    CV_REG_EMM0H = 228,
    CV_REG_EMM1H = 229,
    CV_REG_EMM2H = 230,
    CV_REG_EMM3H = 231,
    CV_REG_EMM4H = 232,
    CV_REG_EMM5H = 233,
    CV_REG_EMM6H = 234,
    CV_REG_EMM7H = 235,

    // do not change the order of these regs, first one must be even too
    CV_REG_MM00 = 236,
    CV_REG_MM01 = 237,
    CV_REG_MM10 = 238,
    CV_REG_MM11 = 239,
    CV_REG_MM20 = 240,
    CV_REG_MM21 = 241,
    CV_REG_MM30 = 242,
    CV_REG_MM31 = 243,
    CV_REG_MM40 = 244,
    CV_REG_MM41 = 245,
    CV_REG_MM50 = 246,
    CV_REG_MM51 = 247,
    CV_REG_MM60 = 248,
    CV_REG_MM61 = 249,
    CV_REG_MM70 = 250,
    CV_REG_MM71 = 251,

    CV_REG_YMM0 = 252, // AVX registers
    CV_REG_YMM1 = 253,
    CV_REG_YMM2 = 254,
    CV_REG_YMM3 = 255,
    CV_REG_YMM4 = 256,
    CV_REG_YMM5 = 257,
    CV_REG_YMM6 = 258,
    CV_REG_YMM7 = 259,

    CV_REG_YMM0H = 260,
    CV_REG_YMM1H = 261,
    CV_REG_YMM2H = 262,
    CV_REG_YMM3H = 263,
    CV_REG_YMM4H = 264,
    CV_REG_YMM5H = 265,
    CV_REG_YMM6H = 266,
    CV_REG_YMM7H = 267,

    CV_REG_YMM0I0 = 268,    // AVX integer registers
    CV_REG_YMM0I1 = 269,
    CV_REG_YMM0I2 = 270,
    CV_REG_YMM0I3 = 271,
    CV_REG_YMM1I0 = 272,
    CV_REG_YMM1I1 = 273,
    CV_REG_YMM1I2 = 274,
    CV_REG_YMM1I3 = 275,
    CV_REG_YMM2I0 = 276,
    CV_REG_YMM2I1 = 277,
    CV_REG_YMM2I2 = 278,
    CV_REG_YMM2I3 = 279,
    CV_REG_YMM3I0 = 280,
    CV_REG_YMM3I1 = 281,
    CV_REG_YMM3I2 = 282,
    CV_REG_YMM3I3 = 283,
    CV_REG_YMM4I0 = 284,
    CV_REG_YMM4I1 = 285,
    CV_REG_YMM4I2 = 286,
    CV_REG_YMM4I3 = 287,
    CV_REG_YMM5I0 = 288,
    CV_REG_YMM5I1 = 289,
    CV_REG_YMM5I2 = 290,
    CV_REG_YMM5I3 = 291,
    CV_REG_YMM6I0 = 292,
    CV_REG_YMM6I1 = 293,
    CV_REG_YMM6I2 = 294,
    CV_REG_YMM6I3 = 295,
    CV_REG_YMM7I0 = 296,
    CV_REG_YMM7I1 = 297,
    CV_REG_YMM7I2 = 298,
    CV_REG_YMM7I3 = 299,

    CV_REG_YMM0F0 = 300,     // AVX floating-point single precise registers
    CV_REG_YMM0F1 = 301,
    CV_REG_YMM0F2 = 302,
    CV_REG_YMM0F3 = 303,
    CV_REG_YMM0F4 = 304,
    CV_REG_YMM0F5 = 305,
    CV_REG_YMM0F6 = 306,
    CV_REG_YMM0F7 = 307,
    CV_REG_YMM1F0 = 308,
    CV_REG_YMM1F1 = 309,
    CV_REG_YMM1F2 = 310,
    CV_REG_YMM1F3 = 311,
    CV_REG_YMM1F4 = 312,
    CV_REG_YMM1F5 = 313,
    CV_REG_YMM1F6 = 314,
    CV_REG_YMM1F7 = 315,
    CV_REG_YMM2F0 = 316,
    CV_REG_YMM2F1 = 317,
    CV_REG_YMM2F2 = 318,
    CV_REG_YMM2F3 = 319,
    CV_REG_YMM2F4 = 320,
    CV_REG_YMM2F5 = 321,
    CV_REG_YMM2F6 = 322,
    CV_REG_YMM2F7 = 323,
    CV_REG_YMM3F0 = 324,
    CV_REG_YMM3F1 = 325,
    CV_REG_YMM3F2 = 326,
    CV_REG_YMM3F3 = 327,
    CV_REG_YMM3F4 = 328,
    CV_REG_YMM3F5 = 329,
    CV_REG_YMM3F6 = 330,
    CV_REG_YMM3F7 = 331,
    CV_REG_YMM4F0 = 332,
    CV_REG_YMM4F1 = 333,
    CV_REG_YMM4F2 = 334,
    CV_REG_YMM4F3 = 335,
    CV_REG_YMM4F4 = 336,
    CV_REG_YMM4F5 = 337,
    CV_REG_YMM4F6 = 338,
    CV_REG_YMM4F7 = 339,
    CV_REG_YMM5F0 = 340,
    CV_REG_YMM5F1 = 341,
    CV_REG_YMM5F2 = 342,
    CV_REG_YMM5F3 = 343,
    CV_REG_YMM5F4 = 344,
    CV_REG_YMM5F5 = 345,
    CV_REG_YMM5F6 = 346,
    CV_REG_YMM5F7 = 347,
    CV_REG_YMM6F0 = 348,
    CV_REG_YMM6F1 = 349,
    CV_REG_YMM6F2 = 350,
    CV_REG_YMM6F3 = 351,
    CV_REG_YMM6F4 = 352,
    CV_REG_YMM6F5 = 353,
    CV_REG_YMM6F6 = 354,
    CV_REG_YMM6F7 = 355,
    CV_REG_YMM7F0 = 356,
    CV_REG_YMM7F1 = 357,
    CV_REG_YMM7F2 = 358,
    CV_REG_YMM7F3 = 359,
    CV_REG_YMM7F4 = 360,
    CV_REG_YMM7F5 = 361,
    CV_REG_YMM7F6 = 362,
    CV_REG_YMM7F7 = 363,

    CV_REG_YMM0D0 = 364,    // AVX floating-point double precise registers
    CV_REG_YMM0D1 = 365,
    CV_REG_YMM0D2 = 366,
    CV_REG_YMM0D3 = 367,
    CV_REG_YMM1D0 = 368,
    CV_REG_YMM1D1 = 369,
    CV_REG_YMM1D2 = 370,
    CV_REG_YMM1D3 = 371,
    CV_REG_YMM2D0 = 372,
    CV_REG_YMM2D1 = 373,
    CV_REG_YMM2D2 = 374,
    CV_REG_YMM2D3 = 375,
    CV_REG_YMM3D0 = 376,
    CV_REG_YMM3D1 = 377,
    CV_REG_YMM3D2 = 378,
    CV_REG_YMM3D3 = 379,
    CV_REG_YMM4D0 = 380,
    CV_REG_YMM4D1 = 381,
    CV_REG_YMM4D2 = 382,
    CV_REG_YMM4D3 = 383,
    CV_REG_YMM5D0 = 384,
    CV_REG_YMM5D1 = 385,
    CV_REG_YMM5D2 = 386,
    CV_REG_YMM5D3 = 387,
    CV_REG_YMM6D0 = 388,
    CV_REG_YMM6D1 = 389,
    CV_REG_YMM6D2 = 390,
    CV_REG_YMM6D3 = 391,
    CV_REG_YMM7D0 = 392,
    CV_REG_YMM7D1 = 393,
    CV_REG_YMM7D2 = 394,
    CV_REG_YMM7D3 = 395,

    CV_REG_BND0 = 396,
    CV_REG_BND1 = 397,
    CV_REG_BND2 = 398,
    CV_REG_BND3 = 399,

    // registers for the 68K processors

    CV_R68_D0 = 0,
    CV_R68_D1 = 1,
    CV_R68_D2 = 2,
    CV_R68_D3 = 3,
    CV_R68_D4 = 4,
    CV_R68_D5 = 5,
    CV_R68_D6 = 6,
    CV_R68_D7 = 7,
    CV_R68_A0 = 8,
    CV_R68_A1 = 9,
    CV_R68_A2 = 10,
    CV_R68_A3 = 11,
    CV_R68_A4 = 12,
    CV_R68_A5 = 13,
    CV_R68_A6 = 14,
    CV_R68_A7 = 15,
    CV_R68_CCR = 16,
    CV_R68_SR = 17,
    CV_R68_USP = 18,
    CV_R68_MSP = 19,
    CV_R68_SFC = 20,
    CV_R68_DFC = 21,
    CV_R68_CACR = 22,
    CV_R68_VBR = 23,
    CV_R68_CAAR = 24,
    CV_R68_ISP = 25,
    CV_R68_PC = 26,
    //reserved  27
    CV_R68_FPCR = 28,
    CV_R68_FPSR = 29,
    CV_R68_FPIAR = 30,
    //reserved  31
    CV_R68_FP0 = 32,
    CV_R68_FP1 = 33,
    CV_R68_FP2 = 34,
    CV_R68_FP3 = 35,
    CV_R68_FP4 = 36,
    CV_R68_FP5 = 37,
    CV_R68_FP6 = 38,
    CV_R68_FP7 = 39,
    //reserved  40
    CV_R68_MMUSR030 = 41,
    CV_R68_MMUSR = 42,
    CV_R68_URP = 43,
    CV_R68_DTT0 = 44,
    CV_R68_DTT1 = 45,
    CV_R68_ITT0 = 46,
    CV_R68_ITT1 = 47,
    //reserved  50
    CV_R68_PSR = 51,
    CV_R68_PCSR = 52,
    CV_R68_VAL = 53,
    CV_R68_CRP = 54,
    CV_R68_SRP = 55,
    CV_R68_DRP = 56,
    CV_R68_TC = 57,
    CV_R68_AC = 58,
    CV_R68_SCC = 59,
    CV_R68_CAL = 60,
    CV_R68_TT0 = 61,
    CV_R68_TT1 = 62,
    //reserved  63
    CV_R68_BAD0 = 64,
    CV_R68_BAD1 = 65,
    CV_R68_BAD2 = 66,
    CV_R68_BAD3 = 67,
    CV_R68_BAD4 = 68,
    CV_R68_BAD5 = 69,
    CV_R68_BAD6 = 70,
    CV_R68_BAD7 = 71,
    CV_R68_BAC0 = 72,
    CV_R68_BAC1 = 73,
    CV_R68_BAC2 = 74,
    CV_R68_BAC3 = 75,
    CV_R68_BAC4 = 76,
    CV_R68_BAC5 = 77,
    CV_R68_BAC6 = 78,
    CV_R68_BAC7 = 79,

    // Register set for the MIPS 4000

    CV_M4_NOREG = CV_REG_NONE,

    CV_M4_IntZERO = 10,      /* CPU REGISTER */
    CV_M4_IntAT = 11,
    CV_M4_IntV0 = 12,
    CV_M4_IntV1 = 13,
    CV_M4_IntA0 = 14,
    CV_M4_IntA1 = 15,
    CV_M4_IntA2 = 16,
    CV_M4_IntA3 = 17,
    CV_M4_IntT0 = 18,
    CV_M4_IntT1 = 19,
    CV_M4_IntT2 = 20,
    CV_M4_IntT3 = 21,
    CV_M4_IntT4 = 22,
    CV_M4_IntT5 = 23,
    CV_M4_IntT6 = 24,
    CV_M4_IntT7 = 25,
    CV_M4_IntS0 = 26,
    CV_M4_IntS1 = 27,
    CV_M4_IntS2 = 28,
    CV_M4_IntS3 = 29,
    CV_M4_IntS4 = 30,
    CV_M4_IntS5 = 31,
    CV_M4_IntS6 = 32,
    CV_M4_IntS7 = 33,
    CV_M4_IntT8 = 34,
    CV_M4_IntT9 = 35,
    CV_M4_IntKT0 = 36,
    CV_M4_IntKT1 = 37,
    CV_M4_IntGP = 38,
    CV_M4_IntSP = 39,
    CV_M4_IntS8 = 40,
    CV_M4_IntRA = 41,
    CV_M4_IntLO = 42,
    CV_M4_IntHI = 43,

    CV_M4_Fir = 50,
    CV_M4_Psr = 51,

    CV_M4_FltF0 = 60,      /* Floating point registers */
    CV_M4_FltF1 = 61,
    CV_M4_FltF2 = 62,
    CV_M4_FltF3 = 63,
    CV_M4_FltF4 = 64,
    CV_M4_FltF5 = 65,
    CV_M4_FltF6 = 66,
    CV_M4_FltF7 = 67,
    CV_M4_FltF8 = 68,
    CV_M4_FltF9 = 69,
    CV_M4_FltF10 = 70,
    CV_M4_FltF11 = 71,
    CV_M4_FltF12 = 72,
    CV_M4_FltF13 = 73,
    CV_M4_FltF14 = 74,
    CV_M4_FltF15 = 75,
    CV_M4_FltF16 = 76,
    CV_M4_FltF17 = 77,
    CV_M4_FltF18 = 78,
    CV_M4_FltF19 = 79,
    CV_M4_FltF20 = 80,
    CV_M4_FltF21 = 81,
    CV_M4_FltF22 = 82,
    CV_M4_FltF23 = 83,
    CV_M4_FltF24 = 84,
    CV_M4_FltF25 = 85,
    CV_M4_FltF26 = 86,
    CV_M4_FltF27 = 87,
    CV_M4_FltF28 = 88,
    CV_M4_FltF29 = 89,
    CV_M4_FltF30 = 90,
    CV_M4_FltF31 = 91,
    CV_M4_FltFsr = 92,


    // Register set for the ALPHA AXP

    CV_ALPHA_NOREG = CV_REG_NONE,

    CV_ALPHA_FltF0 = 10,   // Floating point registers
    CV_ALPHA_FltF1 = 11,
    CV_ALPHA_FltF2 = 12,
    CV_ALPHA_FltF3 = 13,
    CV_ALPHA_FltF4 = 14,
    CV_ALPHA_FltF5 = 15,
    CV_ALPHA_FltF6 = 16,
    CV_ALPHA_FltF7 = 17,
    CV_ALPHA_FltF8 = 18,
    CV_ALPHA_FltF9 = 19,
    CV_ALPHA_FltF10 = 20,
    CV_ALPHA_FltF11 = 21,
    CV_ALPHA_FltF12 = 22,
    CV_ALPHA_FltF13 = 23,
    CV_ALPHA_FltF14 = 24,
    CV_ALPHA_FltF15 = 25,
    CV_ALPHA_FltF16 = 26,
    CV_ALPHA_FltF17 = 27,
    CV_ALPHA_FltF18 = 28,
    CV_ALPHA_FltF19 = 29,
    CV_ALPHA_FltF20 = 30,
    CV_ALPHA_FltF21 = 31,
    CV_ALPHA_FltF22 = 32,
    CV_ALPHA_FltF23 = 33,
    CV_ALPHA_FltF24 = 34,
    CV_ALPHA_FltF25 = 35,
    CV_ALPHA_FltF26 = 36,
    CV_ALPHA_FltF27 = 37,
    CV_ALPHA_FltF28 = 38,
    CV_ALPHA_FltF29 = 39,
    CV_ALPHA_FltF30 = 40,
    CV_ALPHA_FltF31 = 41,

    CV_ALPHA_IntV0 = 42,   // Integer registers
    CV_ALPHA_IntT0 = 43,
    CV_ALPHA_IntT1 = 44,
    CV_ALPHA_IntT2 = 45,
    CV_ALPHA_IntT3 = 46,
    CV_ALPHA_IntT4 = 47,
    CV_ALPHA_IntT5 = 48,
    CV_ALPHA_IntT6 = 49,
    CV_ALPHA_IntT7 = 50,
    CV_ALPHA_IntS0 = 51,
    CV_ALPHA_IntS1 = 52,
    CV_ALPHA_IntS2 = 53,
    CV_ALPHA_IntS3 = 54,
    CV_ALPHA_IntS4 = 55,
    CV_ALPHA_IntS5 = 56,
    CV_ALPHA_IntFP = 57,
    CV_ALPHA_IntA0 = 58,
    CV_ALPHA_IntA1 = 59,
    CV_ALPHA_IntA2 = 60,
    CV_ALPHA_IntA3 = 61,
    CV_ALPHA_IntA4 = 62,
    CV_ALPHA_IntA5 = 63,
    CV_ALPHA_IntT8 = 64,
    CV_ALPHA_IntT9 = 65,
    CV_ALPHA_IntT10 = 66,
    CV_ALPHA_IntT11 = 67,
    CV_ALPHA_IntRA = 68,
    CV_ALPHA_IntT12 = 69,
    CV_ALPHA_IntAT = 70,
    CV_ALPHA_IntGP = 71,
    CV_ALPHA_IntSP = 72,
    CV_ALPHA_IntZERO = 73,


    CV_ALPHA_Fpcr = 74,   // Control registers
    CV_ALPHA_Fir = 75,
    CV_ALPHA_Psr = 76,
    CV_ALPHA_FltFsr = 77,
    CV_ALPHA_SoftFpcr = 78,

    // Register Set for Motorola/IBM PowerPC

    /*
    ** PowerPC General Registers ( User Level )
    */
    CV_PPC_GPR0 = 1,
    CV_PPC_GPR1 = 2,
    CV_PPC_GPR2 = 3,
    CV_PPC_GPR3 = 4,
    CV_PPC_GPR4 = 5,
    CV_PPC_GPR5 = 6,
    CV_PPC_GPR6 = 7,
    CV_PPC_GPR7 = 8,
    CV_PPC_GPR8 = 9,
    CV_PPC_GPR9 = 10,
    CV_PPC_GPR10 = 11,
    CV_PPC_GPR11 = 12,
    CV_PPC_GPR12 = 13,
    CV_PPC_GPR13 = 14,
    CV_PPC_GPR14 = 15,
    CV_PPC_GPR15 = 16,
    CV_PPC_GPR16 = 17,
    CV_PPC_GPR17 = 18,
    CV_PPC_GPR18 = 19,
    CV_PPC_GPR19 = 20,
    CV_PPC_GPR20 = 21,
    CV_PPC_GPR21 = 22,
    CV_PPC_GPR22 = 23,
    CV_PPC_GPR23 = 24,
    CV_PPC_GPR24 = 25,
    CV_PPC_GPR25 = 26,
    CV_PPC_GPR26 = 27,
    CV_PPC_GPR27 = 28,
    CV_PPC_GPR28 = 29,
    CV_PPC_GPR29 = 30,
    CV_PPC_GPR30 = 31,
    CV_PPC_GPR31 = 32,

    /*
    ** PowerPC Condition Register ( User Level )
    */
    CV_PPC_CR = 33,
    CV_PPC_CR0 = 34,
    CV_PPC_CR1 = 35,
    CV_PPC_CR2 = 36,
    CV_PPC_CR3 = 37,
    CV_PPC_CR4 = 38,
    CV_PPC_CR5 = 39,
    CV_PPC_CR6 = 40,
    CV_PPC_CR7 = 41,

    /*
    ** PowerPC Floating Point Registers ( User Level )
    */
    CV_PPC_FPR0 = 42,
    CV_PPC_FPR1 = 43,
    CV_PPC_FPR2 = 44,
    CV_PPC_FPR3 = 45,
    CV_PPC_FPR4 = 46,
    CV_PPC_FPR5 = 47,
    CV_PPC_FPR6 = 48,
    CV_PPC_FPR7 = 49,
    CV_PPC_FPR8 = 50,
    CV_PPC_FPR9 = 51,
    CV_PPC_FPR10 = 52,
    CV_PPC_FPR11 = 53,
    CV_PPC_FPR12 = 54,
    CV_PPC_FPR13 = 55,
    CV_PPC_FPR14 = 56,
    CV_PPC_FPR15 = 57,
    CV_PPC_FPR16 = 58,
    CV_PPC_FPR17 = 59,
    CV_PPC_FPR18 = 60,
    CV_PPC_FPR19 = 61,
    CV_PPC_FPR20 = 62,
    CV_PPC_FPR21 = 63,
    CV_PPC_FPR22 = 64,
    CV_PPC_FPR23 = 65,
    CV_PPC_FPR24 = 66,
    CV_PPC_FPR25 = 67,
    CV_PPC_FPR26 = 68,
    CV_PPC_FPR27 = 69,
    CV_PPC_FPR28 = 70,
    CV_PPC_FPR29 = 71,
    CV_PPC_FPR30 = 72,
    CV_PPC_FPR31 = 73,

    /*
    ** PowerPC Floating Point Status and Control Register ( User Level )
    */
    CV_PPC_FPSCR = 74,

    /*
    ** PowerPC Machine State Register ( Supervisor Level )
    */
    CV_PPC_MSR = 75,

    /*
    ** PowerPC Segment Registers ( Supervisor Level )
    */
    CV_PPC_SR0 = 76,
    CV_PPC_SR1 = 77,
    CV_PPC_SR2 = 78,
    CV_PPC_SR3 = 79,
    CV_PPC_SR4 = 80,
    CV_PPC_SR5 = 81,
    CV_PPC_SR6 = 82,
    CV_PPC_SR7 = 83,
    CV_PPC_SR8 = 84,
    CV_PPC_SR9 = 85,
    CV_PPC_SR10 = 86,
    CV_PPC_SR11 = 87,
    CV_PPC_SR12 = 88,
    CV_PPC_SR13 = 89,
    CV_PPC_SR14 = 90,
    CV_PPC_SR15 = 91,

    /*
    ** For all of the special purpose registers add 100 to the SPR# that the
    ** Motorola/IBM documentation gives with the exception of any imaginary
    ** registers.
    */

    /*
    ** PowerPC Special Purpose Registers ( User Level )
    */
    CV_PPC_PC = 99,     // PC (imaginary register)

    CV_PPC_MQ = 100,    // MPC601
    CV_PPC_XER = 101,
    CV_PPC_RTCU = 104,    // MPC601
    CV_PPC_RTCL = 105,    // MPC601
    CV_PPC_LR = 108,
    CV_PPC_CTR = 109,

    CV_PPC_COMPARE = 110,    // part of XER (internal to the debugger only)
    CV_PPC_COUNT = 111,    // part of XER (internal to the debugger only)

    /*
    ** PowerPC Special Purpose Registers ( Supervisor Level )
    */
    CV_PPC_DSISR = 118,
    CV_PPC_DAR = 119,
    CV_PPC_DEC = 122,
    CV_PPC_SDR1 = 125,
    CV_PPC_SRR0 = 126,
    CV_PPC_SRR1 = 127,
    CV_PPC_SPRG0 = 372,
    CV_PPC_SPRG1 = 373,
    CV_PPC_SPRG2 = 374,
    CV_PPC_SPRG3 = 375,
    CV_PPC_ASR = 280,    // 64-bit implementations only
    CV_PPC_EAR = 382,
    CV_PPC_PVR = 287,
    CV_PPC_BAT0U = 628,
    CV_PPC_BAT0L = 629,
    CV_PPC_BAT1U = 630,
    CV_PPC_BAT1L = 631,
    CV_PPC_BAT2U = 632,
    CV_PPC_BAT2L = 633,
    CV_PPC_BAT3U = 634,
    CV_PPC_BAT3L = 635,
    CV_PPC_DBAT0U = 636,
    CV_PPC_DBAT0L = 637,
    CV_PPC_DBAT1U = 638,
    CV_PPC_DBAT1L = 639,
    CV_PPC_DBAT2U = 640,
    CV_PPC_DBAT2L = 641,
    CV_PPC_DBAT3U = 642,
    CV_PPC_DBAT3L = 643,

    /*
    ** PowerPC Special Purpose Registers Implementation Dependent ( Supervisor Level )
    */

    /*
    ** Doesn't appear that IBM/Motorola has finished defining these.
    */

    CV_PPC_PMR0 = 1044,   // MPC620,
    CV_PPC_PMR1 = 1045,   // MPC620,
    CV_PPC_PMR2 = 1046,   // MPC620,
    CV_PPC_PMR3 = 1047,   // MPC620,
    CV_PPC_PMR4 = 1048,   // MPC620,
    CV_PPC_PMR5 = 1049,   // MPC620,
    CV_PPC_PMR6 = 1050,   // MPC620,
    CV_PPC_PMR7 = 1051,   // MPC620,
    CV_PPC_PMR8 = 1052,   // MPC620,
    CV_PPC_PMR9 = 1053,   // MPC620,
    CV_PPC_PMR10 = 1054,   // MPC620,
    CV_PPC_PMR11 = 1055,   // MPC620,
    CV_PPC_PMR12 = 1056,   // MPC620,
    CV_PPC_PMR13 = 1057,   // MPC620,
    CV_PPC_PMR14 = 1058,   // MPC620,
    CV_PPC_PMR15 = 1059,   // MPC620,

    CV_PPC_DMISS = 1076,   // MPC603
    CV_PPC_DCMP = 1077,   // MPC603
    CV_PPC_HASH1 = 1078,   // MPC603
    CV_PPC_HASH2 = 1079,   // MPC603
    CV_PPC_IMISS = 1080,   // MPC603
    CV_PPC_ICMP = 1081,   // MPC603
    CV_PPC_RPA = 1082,   // MPC603

    CV_PPC_HID0 = 1108,   // MPC601, MPC603, MPC620
    CV_PPC_HID1 = 1109,   // MPC601
    CV_PPC_HID2 = 1110,   // MPC601, MPC603, MPC620 ( IABR )
    CV_PPC_HID3 = 1111,   // Not Defined
    CV_PPC_HID4 = 1112,   // Not Defined
    CV_PPC_HID5 = 1113,   // MPC601, MPC604, MPC620 ( DABR )
    CV_PPC_HID6 = 1114,   // Not Defined
    CV_PPC_HID7 = 1115,   // Not Defined
    CV_PPC_HID8 = 1116,   // MPC620 ( BUSCSR )
    CV_PPC_HID9 = 1117,   // MPC620 ( L2CSR )
    CV_PPC_HID10 = 1118,   // Not Defined
    CV_PPC_HID11 = 1119,   // Not Defined
    CV_PPC_HID12 = 1120,   // Not Defined
    CV_PPC_HID13 = 1121,   // MPC604 ( HCR )
    CV_PPC_HID14 = 1122,   // Not Defined
    CV_PPC_HID15 = 1123,   // MPC601, MPC604, MPC620 ( PIR )

    //
    // JAVA VM registers
    //

    CV_JAVA_PC = 1,

    //
    // Register set for the Hitachi SH3
    //

    CV_SH3_NOREG = CV_REG_NONE,

    CV_SH3_IntR0 = 10,   // CPU REGISTER
    CV_SH3_IntR1 = 11,
    CV_SH3_IntR2 = 12,
    CV_SH3_IntR3 = 13,
    CV_SH3_IntR4 = 14,
    CV_SH3_IntR5 = 15,
    CV_SH3_IntR6 = 16,
    CV_SH3_IntR7 = 17,
    CV_SH3_IntR8 = 18,
    CV_SH3_IntR9 = 19,
    CV_SH3_IntR10 = 20,
    CV_SH3_IntR11 = 21,
    CV_SH3_IntR12 = 22,
    CV_SH3_IntR13 = 23,
    CV_SH3_IntFp = 24,
    CV_SH3_IntSp = 25,
    CV_SH3_Gbr = 38,
    CV_SH3_Pr = 39,
    CV_SH3_Mach = 40,
    CV_SH3_Macl = 41,

    CV_SH3_Pc = 50,
    CV_SH3_Sr = 51,

    CV_SH3_BarA = 60,
    CV_SH3_BasrA = 61,
    CV_SH3_BamrA = 62,
    CV_SH3_BbrA = 63,
    CV_SH3_BarB = 64,
    CV_SH3_BasrB = 65,
    CV_SH3_BamrB = 66,
    CV_SH3_BbrB = 67,
    CV_SH3_BdrB = 68,
    CV_SH3_BdmrB = 69,
    CV_SH3_Brcr = 70,

    //
    // Additional registers for Hitachi SH processors
    //

    CV_SH_Fpscr = 75,    // floating point status/control register
    CV_SH_Fpul = 76,    // floating point communication register

    CV_SH_FpR0 = 80,    // Floating point registers
    CV_SH_FpR1 = 81,
    CV_SH_FpR2 = 82,
    CV_SH_FpR3 = 83,
    CV_SH_FpR4 = 84,
    CV_SH_FpR5 = 85,
    CV_SH_FpR6 = 86,
    CV_SH_FpR7 = 87,
    CV_SH_FpR8 = 88,
    CV_SH_FpR9 = 89,
    CV_SH_FpR10 = 90,
    CV_SH_FpR11 = 91,
    CV_SH_FpR12 = 92,
    CV_SH_FpR13 = 93,
    CV_SH_FpR14 = 94,
    CV_SH_FpR15 = 95,

    CV_SH_XFpR0 = 96,
    CV_SH_XFpR1 = 97,
    CV_SH_XFpR2 = 98,
    CV_SH_XFpR3 = 99,
    CV_SH_XFpR4 = 100,
    CV_SH_XFpR5 = 101,
    CV_SH_XFpR6 = 102,
    CV_SH_XFpR7 = 103,
    CV_SH_XFpR8 = 104,
    CV_SH_XFpR9 = 105,
    CV_SH_XFpR10 = 106,
    CV_SH_XFpR11 = 107,
    CV_SH_XFpR12 = 108,
    CV_SH_XFpR13 = 109,
    CV_SH_XFpR14 = 110,
    CV_SH_XFpR15 = 111,

    //
    // Register set for the ARM processor.
    //

    CV_ARM_NOREG = CV_REG_NONE,

    CV_ARM_R0 = 10,
    CV_ARM_R1 = 11,
    CV_ARM_R2 = 12,
    CV_ARM_R3 = 13,
    CV_ARM_R4 = 14,
    CV_ARM_R5 = 15,
    CV_ARM_R6 = 16,
    CV_ARM_R7 = 17,
    CV_ARM_R8 = 18,
    CV_ARM_R9 = 19,
    CV_ARM_R10 = 20,
    CV_ARM_R11 = 21, // Frame pointer, if allocated
    CV_ARM_R12 = 22,
    CV_ARM_SP = 23, // Stack pointer
    CV_ARM_LR = 24, // Link Register
    CV_ARM_PC = 25, // Program counter
    CV_ARM_CPSR = 26, // Current program status register

    CV_ARM_ACC0 = 27, // DSP co-processor 0 40 bit accumulator

    //
    // Registers for ARM VFP10 support
    //

    CV_ARM_FPSCR = 40,
    CV_ARM_FPEXC = 41,

    CV_ARM_FS0 = 50,
    CV_ARM_FS1 = 51,
    CV_ARM_FS2 = 52,
    CV_ARM_FS3 = 53,
    CV_ARM_FS4 = 54,
    CV_ARM_FS5 = 55,
    CV_ARM_FS6 = 56,
    CV_ARM_FS7 = 57,
    CV_ARM_FS8 = 58,
    CV_ARM_FS9 = 59,
    CV_ARM_FS10 = 60,
    CV_ARM_FS11 = 61,
    CV_ARM_FS12 = 62,
    CV_ARM_FS13 = 63,
    CV_ARM_FS14 = 64,
    CV_ARM_FS15 = 65,
    CV_ARM_FS16 = 66,
    CV_ARM_FS17 = 67,
    CV_ARM_FS18 = 68,
    CV_ARM_FS19 = 69,
    CV_ARM_FS20 = 70,
    CV_ARM_FS21 = 71,
    CV_ARM_FS22 = 72,
    CV_ARM_FS23 = 73,
    CV_ARM_FS24 = 74,
    CV_ARM_FS25 = 75,
    CV_ARM_FS26 = 76,
    CV_ARM_FS27 = 77,
    CV_ARM_FS28 = 78,
    CV_ARM_FS29 = 79,
    CV_ARM_FS30 = 80,
    CV_ARM_FS31 = 81,

    //
    // ARM VFP Floating Point Extra control registers
    //

    CV_ARM_FPEXTRA0 = 90,
    CV_ARM_FPEXTRA1 = 91,
    CV_ARM_FPEXTRA2 = 92,
    CV_ARM_FPEXTRA3 = 93,
    CV_ARM_FPEXTRA4 = 94,
    CV_ARM_FPEXTRA5 = 95,
    CV_ARM_FPEXTRA6 = 96,
    CV_ARM_FPEXTRA7 = 97,

    // XSCALE Concan co-processor registers
    CV_ARM_WR0 = 128,
    CV_ARM_WR1 = 129,
    CV_ARM_WR2 = 130,
    CV_ARM_WR3 = 131,
    CV_ARM_WR4 = 132,
    CV_ARM_WR5 = 133,
    CV_ARM_WR6 = 134,
    CV_ARM_WR7 = 135,
    CV_ARM_WR8 = 136,
    CV_ARM_WR9 = 137,
    CV_ARM_WR10 = 138,
    CV_ARM_WR11 = 139,
    CV_ARM_WR12 = 140,
    CV_ARM_WR13 = 141,
    CV_ARM_WR14 = 142,
    CV_ARM_WR15 = 143,

    // XSCALE Concan co-processor control registers
    CV_ARM_WCID = 144,
    CV_ARM_WCON = 145,
    CV_ARM_WCSSF = 146,
    CV_ARM_WCASF = 147,
    CV_ARM_WC4 = 148,
    CV_ARM_WC5 = 149,
    CV_ARM_WC6 = 150,
    CV_ARM_WC7 = 151,
    CV_ARM_WCGR0 = 152,
    CV_ARM_WCGR1 = 153,
    CV_ARM_WCGR2 = 154,
    CV_ARM_WCGR3 = 155,
    CV_ARM_WC12 = 156,
    CV_ARM_WC13 = 157,
    CV_ARM_WC14 = 158,
    CV_ARM_WC15 = 159,

    //
    // ARM VFPv3/Neon extended floating Point
    //

    CV_ARM_FS32 = 200,
    CV_ARM_FS33 = 201,
    CV_ARM_FS34 = 202,
    CV_ARM_FS35 = 203,
    CV_ARM_FS36 = 204,
    CV_ARM_FS37 = 205,
    CV_ARM_FS38 = 206,
    CV_ARM_FS39 = 207,
    CV_ARM_FS40 = 208,
    CV_ARM_FS41 = 209,
    CV_ARM_FS42 = 210,
    CV_ARM_FS43 = 211,
    CV_ARM_FS44 = 212,
    CV_ARM_FS45 = 213,
    CV_ARM_FS46 = 214,
    CV_ARM_FS47 = 215,
    CV_ARM_FS48 = 216,
    CV_ARM_FS49 = 217,
    CV_ARM_FS50 = 218,
    CV_ARM_FS51 = 219,
    CV_ARM_FS52 = 220,
    CV_ARM_FS53 = 221,
    CV_ARM_FS54 = 222,
    CV_ARM_FS55 = 223,
    CV_ARM_FS56 = 224,
    CV_ARM_FS57 = 225,
    CV_ARM_FS58 = 226,
    CV_ARM_FS59 = 227,
    CV_ARM_FS60 = 228,
    CV_ARM_FS61 = 229,
    CV_ARM_FS62 = 230,
    CV_ARM_FS63 = 231,

    // ARM double-precision floating point

    CV_ARM_ND0 = 300,
    CV_ARM_ND1 = 301,
    CV_ARM_ND2 = 302,
    CV_ARM_ND3 = 303,
    CV_ARM_ND4 = 304,
    CV_ARM_ND5 = 305,
    CV_ARM_ND6 = 306,
    CV_ARM_ND7 = 307,
    CV_ARM_ND8 = 308,
    CV_ARM_ND9 = 309,
    CV_ARM_ND10 = 310,
    CV_ARM_ND11 = 311,
    CV_ARM_ND12 = 312,
    CV_ARM_ND13 = 313,
    CV_ARM_ND14 = 314,
    CV_ARM_ND15 = 315,
    CV_ARM_ND16 = 316,
    CV_ARM_ND17 = 317,
    CV_ARM_ND18 = 318,
    CV_ARM_ND19 = 319,
    CV_ARM_ND20 = 320,
    CV_ARM_ND21 = 321,
    CV_ARM_ND22 = 322,
    CV_ARM_ND23 = 323,
    CV_ARM_ND24 = 324,
    CV_ARM_ND25 = 325,
    CV_ARM_ND26 = 326,
    CV_ARM_ND27 = 327,
    CV_ARM_ND28 = 328,
    CV_ARM_ND29 = 329,
    CV_ARM_ND30 = 330,
    CV_ARM_ND31 = 331,

    // ARM extended precision floating point

    CV_ARM_NQ0 = 400,
    CV_ARM_NQ1 = 401,
    CV_ARM_NQ2 = 402,
    CV_ARM_NQ3 = 403,
    CV_ARM_NQ4 = 404,
    CV_ARM_NQ5 = 405,
    CV_ARM_NQ6 = 406,
    CV_ARM_NQ7 = 407,
    CV_ARM_NQ8 = 408,
    CV_ARM_NQ9 = 409,
    CV_ARM_NQ10 = 410,
    CV_ARM_NQ11 = 411,
    CV_ARM_NQ12 = 412,
    CV_ARM_NQ13 = 413,
    CV_ARM_NQ14 = 414,
    CV_ARM_NQ15 = 415,

    //
    // Register set for ARM64
    //

    CV_ARM64_NOREG = CV_REG_NONE,

    // General purpose 32-bit integer registers

    CV_ARM64_W0 = 10,
    CV_ARM64_W1 = 11,
    CV_ARM64_W2 = 12,
    CV_ARM64_W3 = 13,
    CV_ARM64_W4 = 14,
    CV_ARM64_W5 = 15,
    CV_ARM64_W6 = 16,
    CV_ARM64_W7 = 17,
    CV_ARM64_W8 = 18,
    CV_ARM64_W9 = 19,
    CV_ARM64_W10 = 20,
    CV_ARM64_W11 = 21,
    CV_ARM64_W12 = 22,
    CV_ARM64_W13 = 23,
    CV_ARM64_W14 = 24,
    CV_ARM64_W15 = 25,
    CV_ARM64_W16 = 26,
    CV_ARM64_W17 = 27,
    CV_ARM64_W18 = 28,
    CV_ARM64_W19 = 29,
    CV_ARM64_W20 = 30,
    CV_ARM64_W21 = 31,
    CV_ARM64_W22 = 32,
    CV_ARM64_W23 = 33,
    CV_ARM64_W24 = 34,
    CV_ARM64_W25 = 35,
    CV_ARM64_W26 = 36,
    CV_ARM64_W27 = 37,
    CV_ARM64_W28 = 38,
    CV_ARM64_W29 = 39,
    CV_ARM64_W30 = 40,
    CV_ARM64_WZR = 41,

    // General purpose 64-bit integer registers

    CV_ARM64_X0 = 50,
    CV_ARM64_X1 = 51,
    CV_ARM64_X2 = 52,
    CV_ARM64_X3 = 53,
    CV_ARM64_X4 = 54,
    CV_ARM64_X5 = 55,
    CV_ARM64_X6 = 56,
    CV_ARM64_X7 = 57,
    CV_ARM64_X8 = 58,
    CV_ARM64_X9 = 59,
    CV_ARM64_X10 = 60,
    CV_ARM64_X11 = 61,
    CV_ARM64_X12 = 62,
    CV_ARM64_X13 = 63,
    CV_ARM64_X14 = 64,
    CV_ARM64_X15 = 65,
    CV_ARM64_IP0 = 66,
    CV_ARM64_IP1 = 67,
    CV_ARM64_X18 = 68,
    CV_ARM64_X19 = 69,
    CV_ARM64_X20 = 70,
    CV_ARM64_X21 = 71,
    CV_ARM64_X22 = 72,
    CV_ARM64_X23 = 73,
    CV_ARM64_X24 = 74,
    CV_ARM64_X25 = 75,
    CV_ARM64_X26 = 76,
    CV_ARM64_X27 = 77,
    CV_ARM64_X28 = 78,
    CV_ARM64_FP = 79,
    CV_ARM64_LR = 80,
    CV_ARM64_SP = 81,
    CV_ARM64_ZR = 82,

    // statue register

    CV_ARM64_NZCV = 90,

    // 32-bit floating point registers

    CV_ARM64_S0 = 100,
    CV_ARM64_S1 = 101,
    CV_ARM64_S2 = 102,
    CV_ARM64_S3 = 103,
    CV_ARM64_S4 = 104,
    CV_ARM64_S5 = 105,
    CV_ARM64_S6 = 106,
    CV_ARM64_S7 = 107,
    CV_ARM64_S8 = 108,
    CV_ARM64_S9 = 109,
    CV_ARM64_S10 = 110,
    CV_ARM64_S11 = 111,
    CV_ARM64_S12 = 112,
    CV_ARM64_S13 = 113,
    CV_ARM64_S14 = 114,
    CV_ARM64_S15 = 115,
    CV_ARM64_S16 = 116,
    CV_ARM64_S17 = 117,
    CV_ARM64_S18 = 118,
    CV_ARM64_S19 = 119,
    CV_ARM64_S20 = 120,
    CV_ARM64_S21 = 121,
    CV_ARM64_S22 = 122,
    CV_ARM64_S23 = 123,
    CV_ARM64_S24 = 124,
    CV_ARM64_S25 = 125,
    CV_ARM64_S26 = 126,
    CV_ARM64_S27 = 127,
    CV_ARM64_S28 = 128,
    CV_ARM64_S29 = 129,
    CV_ARM64_S30 = 130,
    CV_ARM64_S31 = 131,

    // 64-bit floating point registers

    CV_ARM64_D0 = 140,
    CV_ARM64_D1 = 141,
    CV_ARM64_D2 = 142,
    CV_ARM64_D3 = 143,
    CV_ARM64_D4 = 144,
    CV_ARM64_D5 = 145,
    CV_ARM64_D6 = 146,
    CV_ARM64_D7 = 147,
    CV_ARM64_D8 = 148,
    CV_ARM64_D9 = 149,
    CV_ARM64_D10 = 150,
    CV_ARM64_D11 = 151,
    CV_ARM64_D12 = 152,
    CV_ARM64_D13 = 153,
    CV_ARM64_D14 = 154,
    CV_ARM64_D15 = 155,
    CV_ARM64_D16 = 156,
    CV_ARM64_D17 = 157,
    CV_ARM64_D18 = 158,
    CV_ARM64_D19 = 159,
    CV_ARM64_D20 = 160,
    CV_ARM64_D21 = 161,
    CV_ARM64_D22 = 162,
    CV_ARM64_D23 = 163,
    CV_ARM64_D24 = 164,
    CV_ARM64_D25 = 165,
    CV_ARM64_D26 = 166,
    CV_ARM64_D27 = 167,
    CV_ARM64_D28 = 168,
    CV_ARM64_D29 = 169,
    CV_ARM64_D30 = 170,
    CV_ARM64_D31 = 171,

    // 128-bit SIMD registers

    CV_ARM64_Q0 = 180,
    CV_ARM64_Q1 = 181,
    CV_ARM64_Q2 = 182,
    CV_ARM64_Q3 = 183,
    CV_ARM64_Q4 = 184,
    CV_ARM64_Q5 = 185,
    CV_ARM64_Q6 = 186,
    CV_ARM64_Q7 = 187,
    CV_ARM64_Q8 = 188,
    CV_ARM64_Q9 = 189,
    CV_ARM64_Q10 = 190,
    CV_ARM64_Q11 = 191,
    CV_ARM64_Q12 = 192,
    CV_ARM64_Q13 = 193,
    CV_ARM64_Q14 = 194,
    CV_ARM64_Q15 = 195,
    CV_ARM64_Q16 = 196,
    CV_ARM64_Q17 = 197,
    CV_ARM64_Q18 = 198,
    CV_ARM64_Q19 = 199,
    CV_ARM64_Q20 = 200,
    CV_ARM64_Q21 = 201,
    CV_ARM64_Q22 = 202,
    CV_ARM64_Q23 = 203,
    CV_ARM64_Q24 = 204,
    CV_ARM64_Q25 = 205,
    CV_ARM64_Q26 = 206,
    CV_ARM64_Q27 = 207,
    CV_ARM64_Q28 = 208,
    CV_ARM64_Q29 = 209,
    CV_ARM64_Q30 = 210,
    CV_ARM64_Q31 = 211,

    // Floating point status register

    CV_ARM64_FPSR = 220,

    //
    // Register set for Intel IA64
    //

    CV_IA64_NOREG = CV_REG_NONE,

    // Branch Registers

    CV_IA64_Br0 = 512,
    CV_IA64_Br1 = 513,
    CV_IA64_Br2 = 514,
    CV_IA64_Br3 = 515,
    CV_IA64_Br4 = 516,
    CV_IA64_Br5 = 517,
    CV_IA64_Br6 = 518,
    CV_IA64_Br7 = 519,

    // Predicate Registers

    CV_IA64_P0 = 704,
    CV_IA64_P1 = 705,
    CV_IA64_P2 = 706,
    CV_IA64_P3 = 707,
    CV_IA64_P4 = 708,
    CV_IA64_P5 = 709,
    CV_IA64_P6 = 710,
    CV_IA64_P7 = 711,
    CV_IA64_P8 = 712,
    CV_IA64_P9 = 713,
    CV_IA64_P10 = 714,
    CV_IA64_P11 = 715,
    CV_IA64_P12 = 716,
    CV_IA64_P13 = 717,
    CV_IA64_P14 = 718,
    CV_IA64_P15 = 719,
    CV_IA64_P16 = 720,
    CV_IA64_P17 = 721,
    CV_IA64_P18 = 722,
    CV_IA64_P19 = 723,
    CV_IA64_P20 = 724,
    CV_IA64_P21 = 725,
    CV_IA64_P22 = 726,
    CV_IA64_P23 = 727,
    CV_IA64_P24 = 728,
    CV_IA64_P25 = 729,
    CV_IA64_P26 = 730,
    CV_IA64_P27 = 731,
    CV_IA64_P28 = 732,
    CV_IA64_P29 = 733,
    CV_IA64_P30 = 734,
    CV_IA64_P31 = 735,
    CV_IA64_P32 = 736,
    CV_IA64_P33 = 737,
    CV_IA64_P34 = 738,
    CV_IA64_P35 = 739,
    CV_IA64_P36 = 740,
    CV_IA64_P37 = 741,
    CV_IA64_P38 = 742,
    CV_IA64_P39 = 743,
    CV_IA64_P40 = 744,
    CV_IA64_P41 = 745,
    CV_IA64_P42 = 746,
    CV_IA64_P43 = 747,
    CV_IA64_P44 = 748,
    CV_IA64_P45 = 749,
    CV_IA64_P46 = 750,
    CV_IA64_P47 = 751,
    CV_IA64_P48 = 752,
    CV_IA64_P49 = 753,
    CV_IA64_P50 = 754,
    CV_IA64_P51 = 755,
    CV_IA64_P52 = 756,
    CV_IA64_P53 = 757,
    CV_IA64_P54 = 758,
    CV_IA64_P55 = 759,
    CV_IA64_P56 = 760,
    CV_IA64_P57 = 761,
    CV_IA64_P58 = 762,
    CV_IA64_P59 = 763,
    CV_IA64_P60 = 764,
    CV_IA64_P61 = 765,
    CV_IA64_P62 = 766,
    CV_IA64_P63 = 767,

    CV_IA64_Preds = 768,

    // Banked General Registers

    CV_IA64_IntH0 = 832,
    CV_IA64_IntH1 = 833,
    CV_IA64_IntH2 = 834,
    CV_IA64_IntH3 = 835,
    CV_IA64_IntH4 = 836,
    CV_IA64_IntH5 = 837,
    CV_IA64_IntH6 = 838,
    CV_IA64_IntH7 = 839,
    CV_IA64_IntH8 = 840,
    CV_IA64_IntH9 = 841,
    CV_IA64_IntH10 = 842,
    CV_IA64_IntH11 = 843,
    CV_IA64_IntH12 = 844,
    CV_IA64_IntH13 = 845,
    CV_IA64_IntH14 = 846,
    CV_IA64_IntH15 = 847,

    // Special Registers

    CV_IA64_Ip = 1016,
    CV_IA64_Umask = 1017,
    CV_IA64_Cfm = 1018,
    CV_IA64_Psr = 1019,

    // Banked General Registers

    CV_IA64_Nats = 1020,
    CV_IA64_Nats2 = 1021,
    CV_IA64_Nats3 = 1022,

    // General-Purpose Registers

    // Integer registers
    CV_IA64_IntR0 = 1024,
    CV_IA64_IntR1 = 1025,
    CV_IA64_IntR2 = 1026,
    CV_IA64_IntR3 = 1027,
    CV_IA64_IntR4 = 1028,
    CV_IA64_IntR5 = 1029,
    CV_IA64_IntR6 = 1030,
    CV_IA64_IntR7 = 1031,
    CV_IA64_IntR8 = 1032,
    CV_IA64_IntR9 = 1033,
    CV_IA64_IntR10 = 1034,
    CV_IA64_IntR11 = 1035,
    CV_IA64_IntR12 = 1036,
    CV_IA64_IntR13 = 1037,
    CV_IA64_IntR14 = 1038,
    CV_IA64_IntR15 = 1039,
    CV_IA64_IntR16 = 1040,
    CV_IA64_IntR17 = 1041,
    CV_IA64_IntR18 = 1042,
    CV_IA64_IntR19 = 1043,
    CV_IA64_IntR20 = 1044,
    CV_IA64_IntR21 = 1045,
    CV_IA64_IntR22 = 1046,
    CV_IA64_IntR23 = 1047,
    CV_IA64_IntR24 = 1048,
    CV_IA64_IntR25 = 1049,
    CV_IA64_IntR26 = 1050,
    CV_IA64_IntR27 = 1051,
    CV_IA64_IntR28 = 1052,
    CV_IA64_IntR29 = 1053,
    CV_IA64_IntR30 = 1054,
    CV_IA64_IntR31 = 1055,

    // Register Stack
    CV_IA64_IntR32 = 1056,
    CV_IA64_IntR33 = 1057,
    CV_IA64_IntR34 = 1058,
    CV_IA64_IntR35 = 1059,
    CV_IA64_IntR36 = 1060,
    CV_IA64_IntR37 = 1061,
    CV_IA64_IntR38 = 1062,
    CV_IA64_IntR39 = 1063,
    CV_IA64_IntR40 = 1064,
    CV_IA64_IntR41 = 1065,
    CV_IA64_IntR42 = 1066,
    CV_IA64_IntR43 = 1067,
    CV_IA64_IntR44 = 1068,
    CV_IA64_IntR45 = 1069,
    CV_IA64_IntR46 = 1070,
    CV_IA64_IntR47 = 1071,
    CV_IA64_IntR48 = 1072,
    CV_IA64_IntR49 = 1073,
    CV_IA64_IntR50 = 1074,
    CV_IA64_IntR51 = 1075,
    CV_IA64_IntR52 = 1076,
    CV_IA64_IntR53 = 1077,
    CV_IA64_IntR54 = 1078,
    CV_IA64_IntR55 = 1079,
    CV_IA64_IntR56 = 1080,
    CV_IA64_IntR57 = 1081,
    CV_IA64_IntR58 = 1082,
    CV_IA64_IntR59 = 1083,
    CV_IA64_IntR60 = 1084,
    CV_IA64_IntR61 = 1085,
    CV_IA64_IntR62 = 1086,
    CV_IA64_IntR63 = 1087,
    CV_IA64_IntR64 = 1088,
    CV_IA64_IntR65 = 1089,
    CV_IA64_IntR66 = 1090,
    CV_IA64_IntR67 = 1091,
    CV_IA64_IntR68 = 1092,
    CV_IA64_IntR69 = 1093,
    CV_IA64_IntR70 = 1094,
    CV_IA64_IntR71 = 1095,
    CV_IA64_IntR72 = 1096,
    CV_IA64_IntR73 = 1097,
    CV_IA64_IntR74 = 1098,
    CV_IA64_IntR75 = 1099,
    CV_IA64_IntR76 = 1100,
    CV_IA64_IntR77 = 1101,
    CV_IA64_IntR78 = 1102,
    CV_IA64_IntR79 = 1103,
    CV_IA64_IntR80 = 1104,
    CV_IA64_IntR81 = 1105,
    CV_IA64_IntR82 = 1106,
    CV_IA64_IntR83 = 1107,
    CV_IA64_IntR84 = 1108,
    CV_IA64_IntR85 = 1109,
    CV_IA64_IntR86 = 1110,
    CV_IA64_IntR87 = 1111,
    CV_IA64_IntR88 = 1112,
    CV_IA64_IntR89 = 1113,
    CV_IA64_IntR90 = 1114,
    CV_IA64_IntR91 = 1115,
    CV_IA64_IntR92 = 1116,
    CV_IA64_IntR93 = 1117,
    CV_IA64_IntR94 = 1118,
    CV_IA64_IntR95 = 1119,
    CV_IA64_IntR96 = 1120,
    CV_IA64_IntR97 = 1121,
    CV_IA64_IntR98 = 1122,
    CV_IA64_IntR99 = 1123,
    CV_IA64_IntR100 = 1124,
    CV_IA64_IntR101 = 1125,
    CV_IA64_IntR102 = 1126,
    CV_IA64_IntR103 = 1127,
    CV_IA64_IntR104 = 1128,
    CV_IA64_IntR105 = 1129,
    CV_IA64_IntR106 = 1130,
    CV_IA64_IntR107 = 1131,
    CV_IA64_IntR108 = 1132,
    CV_IA64_IntR109 = 1133,
    CV_IA64_IntR110 = 1134,
    CV_IA64_IntR111 = 1135,
    CV_IA64_IntR112 = 1136,
    CV_IA64_IntR113 = 1137,
    CV_IA64_IntR114 = 1138,
    CV_IA64_IntR115 = 1139,
    CV_IA64_IntR116 = 1140,
    CV_IA64_IntR117 = 1141,
    CV_IA64_IntR118 = 1142,
    CV_IA64_IntR119 = 1143,
    CV_IA64_IntR120 = 1144,
    CV_IA64_IntR121 = 1145,
    CV_IA64_IntR122 = 1146,
    CV_IA64_IntR123 = 1147,
    CV_IA64_IntR124 = 1148,
    CV_IA64_IntR125 = 1149,
    CV_IA64_IntR126 = 1150,
    CV_IA64_IntR127 = 1151,

    // Floating-Point Registers

    // Low Floating Point Registers
    CV_IA64_FltF0 = 2048,
    CV_IA64_FltF1 = 2049,
    CV_IA64_FltF2 = 2050,
    CV_IA64_FltF3 = 2051,
    CV_IA64_FltF4 = 2052,
    CV_IA64_FltF5 = 2053,
    CV_IA64_FltF6 = 2054,
    CV_IA64_FltF7 = 2055,
    CV_IA64_FltF8 = 2056,
    CV_IA64_FltF9 = 2057,
    CV_IA64_FltF10 = 2058,
    CV_IA64_FltF11 = 2059,
    CV_IA64_FltF12 = 2060,
    CV_IA64_FltF13 = 2061,
    CV_IA64_FltF14 = 2062,
    CV_IA64_FltF15 = 2063,
    CV_IA64_FltF16 = 2064,
    CV_IA64_FltF17 = 2065,
    CV_IA64_FltF18 = 2066,
    CV_IA64_FltF19 = 2067,
    CV_IA64_FltF20 = 2068,
    CV_IA64_FltF21 = 2069,
    CV_IA64_FltF22 = 2070,
    CV_IA64_FltF23 = 2071,
    CV_IA64_FltF24 = 2072,
    CV_IA64_FltF25 = 2073,
    CV_IA64_FltF26 = 2074,
    CV_IA64_FltF27 = 2075,
    CV_IA64_FltF28 = 2076,
    CV_IA64_FltF29 = 2077,
    CV_IA64_FltF30 = 2078,
    CV_IA64_FltF31 = 2079,

    // High Floating Point Registers
    CV_IA64_FltF32 = 2080,
    CV_IA64_FltF33 = 2081,
    CV_IA64_FltF34 = 2082,
    CV_IA64_FltF35 = 2083,
    CV_IA64_FltF36 = 2084,
    CV_IA64_FltF37 = 2085,
    CV_IA64_FltF38 = 2086,
    CV_IA64_FltF39 = 2087,
    CV_IA64_FltF40 = 2088,
    CV_IA64_FltF41 = 2089,
    CV_IA64_FltF42 = 2090,
    CV_IA64_FltF43 = 2091,
    CV_IA64_FltF44 = 2092,
    CV_IA64_FltF45 = 2093,
    CV_IA64_FltF46 = 2094,
    CV_IA64_FltF47 = 2095,
    CV_IA64_FltF48 = 2096,
    CV_IA64_FltF49 = 2097,
    CV_IA64_FltF50 = 2098,
    CV_IA64_FltF51 = 2099,
    CV_IA64_FltF52 = 2100,
    CV_IA64_FltF53 = 2101,
    CV_IA64_FltF54 = 2102,
    CV_IA64_FltF55 = 2103,
    CV_IA64_FltF56 = 2104,
    CV_IA64_FltF57 = 2105,
    CV_IA64_FltF58 = 2106,
    CV_IA64_FltF59 = 2107,
    CV_IA64_FltF60 = 2108,
    CV_IA64_FltF61 = 2109,
    CV_IA64_FltF62 = 2110,
    CV_IA64_FltF63 = 2111,
    CV_IA64_FltF64 = 2112,
    CV_IA64_FltF65 = 2113,
    CV_IA64_FltF66 = 2114,
    CV_IA64_FltF67 = 2115,
    CV_IA64_FltF68 = 2116,
    CV_IA64_FltF69 = 2117,
    CV_IA64_FltF70 = 2118,
    CV_IA64_FltF71 = 2119,
    CV_IA64_FltF72 = 2120,
    CV_IA64_FltF73 = 2121,
    CV_IA64_FltF74 = 2122,
    CV_IA64_FltF75 = 2123,
    CV_IA64_FltF76 = 2124,
    CV_IA64_FltF77 = 2125,
    CV_IA64_FltF78 = 2126,
    CV_IA64_FltF79 = 2127,
    CV_IA64_FltF80 = 2128,
    CV_IA64_FltF81 = 2129,
    CV_IA64_FltF82 = 2130,
    CV_IA64_FltF83 = 2131,
    CV_IA64_FltF84 = 2132,
    CV_IA64_FltF85 = 2133,
    CV_IA64_FltF86 = 2134,
    CV_IA64_FltF87 = 2135,
    CV_IA64_FltF88 = 2136,
    CV_IA64_FltF89 = 2137,
    CV_IA64_FltF90 = 2138,
    CV_IA64_FltF91 = 2139,
    CV_IA64_FltF92 = 2140,
    CV_IA64_FltF93 = 2141,
    CV_IA64_FltF94 = 2142,
    CV_IA64_FltF95 = 2143,
    CV_IA64_FltF96 = 2144,
    CV_IA64_FltF97 = 2145,
    CV_IA64_FltF98 = 2146,
    CV_IA64_FltF99 = 2147,
    CV_IA64_FltF100 = 2148,
    CV_IA64_FltF101 = 2149,
    CV_IA64_FltF102 = 2150,
    CV_IA64_FltF103 = 2151,
    CV_IA64_FltF104 = 2152,
    CV_IA64_FltF105 = 2153,
    CV_IA64_FltF106 = 2154,
    CV_IA64_FltF107 = 2155,
    CV_IA64_FltF108 = 2156,
    CV_IA64_FltF109 = 2157,
    CV_IA64_FltF110 = 2158,
    CV_IA64_FltF111 = 2159,
    CV_IA64_FltF112 = 2160,
    CV_IA64_FltF113 = 2161,
    CV_IA64_FltF114 = 2162,
    CV_IA64_FltF115 = 2163,
    CV_IA64_FltF116 = 2164,
    CV_IA64_FltF117 = 2165,
    CV_IA64_FltF118 = 2166,
    CV_IA64_FltF119 = 2167,
    CV_IA64_FltF120 = 2168,
    CV_IA64_FltF121 = 2169,
    CV_IA64_FltF122 = 2170,
    CV_IA64_FltF123 = 2171,
    CV_IA64_FltF124 = 2172,
    CV_IA64_FltF125 = 2173,
    CV_IA64_FltF126 = 2174,
    CV_IA64_FltF127 = 2175,

    // Application Registers

    CV_IA64_ApKR0 = 3072,
    CV_IA64_ApKR1 = 3073,
    CV_IA64_ApKR2 = 3074,
    CV_IA64_ApKR3 = 3075,
    CV_IA64_ApKR4 = 3076,
    CV_IA64_ApKR5 = 3077,
    CV_IA64_ApKR6 = 3078,
    CV_IA64_ApKR7 = 3079,
    CV_IA64_AR8 = 3080,
    CV_IA64_AR9 = 3081,
    CV_IA64_AR10 = 3082,
    CV_IA64_AR11 = 3083,
    CV_IA64_AR12 = 3084,
    CV_IA64_AR13 = 3085,
    CV_IA64_AR14 = 3086,
    CV_IA64_AR15 = 3087,
    CV_IA64_RsRSC = 3088,
    CV_IA64_RsBSP = 3089,
    CV_IA64_RsBSPSTORE = 3090,
    CV_IA64_RsRNAT = 3091,
    CV_IA64_AR20 = 3092,
    CV_IA64_StFCR = 3093,
    CV_IA64_AR22 = 3094,
    CV_IA64_AR23 = 3095,
    CV_IA64_EFLAG = 3096,
    CV_IA64_CSD = 3097,
    CV_IA64_SSD = 3098,
    CV_IA64_CFLG = 3099,
    CV_IA64_StFSR = 3100,
    CV_IA64_StFIR = 3101,
    CV_IA64_StFDR = 3102,
    CV_IA64_AR31 = 3103,
    CV_IA64_ApCCV = 3104,
    CV_IA64_AR33 = 3105,
    CV_IA64_AR34 = 3106,
    CV_IA64_AR35 = 3107,
    CV_IA64_ApUNAT = 3108,
    CV_IA64_AR37 = 3109,
    CV_IA64_AR38 = 3110,
    CV_IA64_AR39 = 3111,
    CV_IA64_StFPSR = 3112,
    CV_IA64_AR41 = 3113,
    CV_IA64_AR42 = 3114,
    CV_IA64_AR43 = 3115,
    CV_IA64_ApITC = 3116,
    CV_IA64_AR45 = 3117,
    CV_IA64_AR46 = 3118,
    CV_IA64_AR47 = 3119,
    CV_IA64_AR48 = 3120,
    CV_IA64_AR49 = 3121,
    CV_IA64_AR50 = 3122,
    CV_IA64_AR51 = 3123,
    CV_IA64_AR52 = 3124,
    CV_IA64_AR53 = 3125,
    CV_IA64_AR54 = 3126,
    CV_IA64_AR55 = 3127,
    CV_IA64_AR56 = 3128,
    CV_IA64_AR57 = 3129,
    CV_IA64_AR58 = 3130,
    CV_IA64_AR59 = 3131,
    CV_IA64_AR60 = 3132,
    CV_IA64_AR61 = 3133,
    CV_IA64_AR62 = 3134,
    CV_IA64_AR63 = 3135,
    CV_IA64_RsPFS = 3136,
    CV_IA64_ApLC = 3137,
    CV_IA64_ApEC = 3138,
    CV_IA64_AR67 = 3139,
    CV_IA64_AR68 = 3140,
    CV_IA64_AR69 = 3141,
    CV_IA64_AR70 = 3142,
    CV_IA64_AR71 = 3143,
    CV_IA64_AR72 = 3144,
    CV_IA64_AR73 = 3145,
    CV_IA64_AR74 = 3146,
    CV_IA64_AR75 = 3147,
    CV_IA64_AR76 = 3148,
    CV_IA64_AR77 = 3149,
    CV_IA64_AR78 = 3150,
    CV_IA64_AR79 = 3151,
    CV_IA64_AR80 = 3152,
    CV_IA64_AR81 = 3153,
    CV_IA64_AR82 = 3154,
    CV_IA64_AR83 = 3155,
    CV_IA64_AR84 = 3156,
    CV_IA64_AR85 = 3157,
    CV_IA64_AR86 = 3158,
    CV_IA64_AR87 = 3159,
    CV_IA64_AR88 = 3160,
    CV_IA64_AR89 = 3161,
    CV_IA64_AR90 = 3162,
    CV_IA64_AR91 = 3163,
    CV_IA64_AR92 = 3164,
    CV_IA64_AR93 = 3165,
    CV_IA64_AR94 = 3166,
    CV_IA64_AR95 = 3167,
    CV_IA64_AR96 = 3168,
    CV_IA64_AR97 = 3169,
    CV_IA64_AR98 = 3170,
    CV_IA64_AR99 = 3171,
    CV_IA64_AR100 = 3172,
    CV_IA64_AR101 = 3173,
    CV_IA64_AR102 = 3174,
    CV_IA64_AR103 = 3175,
    CV_IA64_AR104 = 3176,
    CV_IA64_AR105 = 3177,
    CV_IA64_AR106 = 3178,
    CV_IA64_AR107 = 3179,
    CV_IA64_AR108 = 3180,
    CV_IA64_AR109 = 3181,
    CV_IA64_AR110 = 3182,
    CV_IA64_AR111 = 3183,
    CV_IA64_AR112 = 3184,
    CV_IA64_AR113 = 3185,
    CV_IA64_AR114 = 3186,
    CV_IA64_AR115 = 3187,
    CV_IA64_AR116 = 3188,
    CV_IA64_AR117 = 3189,
    CV_IA64_AR118 = 3190,
    CV_IA64_AR119 = 3191,
    CV_IA64_AR120 = 3192,
    CV_IA64_AR121 = 3193,
    CV_IA64_AR122 = 3194,
    CV_IA64_AR123 = 3195,
    CV_IA64_AR124 = 3196,
    CV_IA64_AR125 = 3197,
    CV_IA64_AR126 = 3198,
    CV_IA64_AR127 = 3199,

    // CPUID Registers

    CV_IA64_CPUID0 = 3328,
    CV_IA64_CPUID1 = 3329,
    CV_IA64_CPUID2 = 3330,
    CV_IA64_CPUID3 = 3331,
    CV_IA64_CPUID4 = 3332,

    // Control Registers

    CV_IA64_ApDCR = 4096,
    CV_IA64_ApITM = 4097,
    CV_IA64_ApIVA = 4098,
    CV_IA64_CR3 = 4099,
    CV_IA64_CR4 = 4100,
    CV_IA64_CR5 = 4101,
    CV_IA64_CR6 = 4102,
    CV_IA64_CR7 = 4103,
    CV_IA64_ApPTA = 4104,
    CV_IA64_ApGPTA = 4105,
    CV_IA64_CR10 = 4106,
    CV_IA64_CR11 = 4107,
    CV_IA64_CR12 = 4108,
    CV_IA64_CR13 = 4109,
    CV_IA64_CR14 = 4110,
    CV_IA64_CR15 = 4111,
    CV_IA64_StIPSR = 4112,
    CV_IA64_StISR = 4113,
    CV_IA64_CR18 = 4114,
    CV_IA64_StIIP = 4115,
    CV_IA64_StIFA = 4116,
    CV_IA64_StITIR = 4117,
    CV_IA64_StIIPA = 4118,
    CV_IA64_StIFS = 4119,
    CV_IA64_StIIM = 4120,
    CV_IA64_StIHA = 4121,
    CV_IA64_CR26 = 4122,
    CV_IA64_CR27 = 4123,
    CV_IA64_CR28 = 4124,
    CV_IA64_CR29 = 4125,
    CV_IA64_CR30 = 4126,
    CV_IA64_CR31 = 4127,
    CV_IA64_CR32 = 4128,
    CV_IA64_CR33 = 4129,
    CV_IA64_CR34 = 4130,
    CV_IA64_CR35 = 4131,
    CV_IA64_CR36 = 4132,
    CV_IA64_CR37 = 4133,
    CV_IA64_CR38 = 4134,
    CV_IA64_CR39 = 4135,
    CV_IA64_CR40 = 4136,
    CV_IA64_CR41 = 4137,
    CV_IA64_CR42 = 4138,
    CV_IA64_CR43 = 4139,
    CV_IA64_CR44 = 4140,
    CV_IA64_CR45 = 4141,
    CV_IA64_CR46 = 4142,
    CV_IA64_CR47 = 4143,
    CV_IA64_CR48 = 4144,
    CV_IA64_CR49 = 4145,
    CV_IA64_CR50 = 4146,
    CV_IA64_CR51 = 4147,
    CV_IA64_CR52 = 4148,
    CV_IA64_CR53 = 4149,
    CV_IA64_CR54 = 4150,
    CV_IA64_CR55 = 4151,
    CV_IA64_CR56 = 4152,
    CV_IA64_CR57 = 4153,
    CV_IA64_CR58 = 4154,
    CV_IA64_CR59 = 4155,
    CV_IA64_CR60 = 4156,
    CV_IA64_CR61 = 4157,
    CV_IA64_CR62 = 4158,
    CV_IA64_CR63 = 4159,
    CV_IA64_SaLID = 4160,
    CV_IA64_SaIVR = 4161,
    CV_IA64_SaTPR = 4162,
    CV_IA64_SaEOI = 4163,
    CV_IA64_SaIRR0 = 4164,
    CV_IA64_SaIRR1 = 4165,
    CV_IA64_SaIRR2 = 4166,
    CV_IA64_SaIRR3 = 4167,
    CV_IA64_SaITV = 4168,
    CV_IA64_SaPMV = 4169,
    CV_IA64_SaCMCV = 4170,
    CV_IA64_CR75 = 4171,
    CV_IA64_CR76 = 4172,
    CV_IA64_CR77 = 4173,
    CV_IA64_CR78 = 4174,
    CV_IA64_CR79 = 4175,
    CV_IA64_SaLRR0 = 4176,
    CV_IA64_SaLRR1 = 4177,
    CV_IA64_CR82 = 4178,
    CV_IA64_CR83 = 4179,
    CV_IA64_CR84 = 4180,
    CV_IA64_CR85 = 4181,
    CV_IA64_CR86 = 4182,
    CV_IA64_CR87 = 4183,
    CV_IA64_CR88 = 4184,
    CV_IA64_CR89 = 4185,
    CV_IA64_CR90 = 4186,
    CV_IA64_CR91 = 4187,
    CV_IA64_CR92 = 4188,
    CV_IA64_CR93 = 4189,
    CV_IA64_CR94 = 4190,
    CV_IA64_CR95 = 4191,
    CV_IA64_CR96 = 4192,
    CV_IA64_CR97 = 4193,
    CV_IA64_CR98 = 4194,
    CV_IA64_CR99 = 4195,
    CV_IA64_CR100 = 4196,
    CV_IA64_CR101 = 4197,
    CV_IA64_CR102 = 4198,
    CV_IA64_CR103 = 4199,
    CV_IA64_CR104 = 4200,
    CV_IA64_CR105 = 4201,
    CV_IA64_CR106 = 4202,
    CV_IA64_CR107 = 4203,
    CV_IA64_CR108 = 4204,
    CV_IA64_CR109 = 4205,
    CV_IA64_CR110 = 4206,
    CV_IA64_CR111 = 4207,
    CV_IA64_CR112 = 4208,
    CV_IA64_CR113 = 4209,
    CV_IA64_CR114 = 4210,
    CV_IA64_CR115 = 4211,
    CV_IA64_CR116 = 4212,
    CV_IA64_CR117 = 4213,
    CV_IA64_CR118 = 4214,
    CV_IA64_CR119 = 4215,
    CV_IA64_CR120 = 4216,
    CV_IA64_CR121 = 4217,
    CV_IA64_CR122 = 4218,
    CV_IA64_CR123 = 4219,
    CV_IA64_CR124 = 4220,
    CV_IA64_CR125 = 4221,
    CV_IA64_CR126 = 4222,
    CV_IA64_CR127 = 4223,

    // Protection Key Registers

    CV_IA64_Pkr0 = 5120,
    CV_IA64_Pkr1 = 5121,
    CV_IA64_Pkr2 = 5122,
    CV_IA64_Pkr3 = 5123,
    CV_IA64_Pkr4 = 5124,
    CV_IA64_Pkr5 = 5125,
    CV_IA64_Pkr6 = 5126,
    CV_IA64_Pkr7 = 5127,
    CV_IA64_Pkr8 = 5128,
    CV_IA64_Pkr9 = 5129,
    CV_IA64_Pkr10 = 5130,
    CV_IA64_Pkr11 = 5131,
    CV_IA64_Pkr12 = 5132,
    CV_IA64_Pkr13 = 5133,
    CV_IA64_Pkr14 = 5134,
    CV_IA64_Pkr15 = 5135,

    // Region Registers

    CV_IA64_Rr0 = 6144,
    CV_IA64_Rr1 = 6145,
    CV_IA64_Rr2 = 6146,
    CV_IA64_Rr3 = 6147,
    CV_IA64_Rr4 = 6148,
    CV_IA64_Rr5 = 6149,
    CV_IA64_Rr6 = 6150,
    CV_IA64_Rr7 = 6151,

    // Performance Monitor Data Registers

    CV_IA64_PFD0 = 7168,
    CV_IA64_PFD1 = 7169,
    CV_IA64_PFD2 = 7170,
    CV_IA64_PFD3 = 7171,
    CV_IA64_PFD4 = 7172,
    CV_IA64_PFD5 = 7173,
    CV_IA64_PFD6 = 7174,
    CV_IA64_PFD7 = 7175,
    CV_IA64_PFD8 = 7176,
    CV_IA64_PFD9 = 7177,
    CV_IA64_PFD10 = 7178,
    CV_IA64_PFD11 = 7179,
    CV_IA64_PFD12 = 7180,
    CV_IA64_PFD13 = 7181,
    CV_IA64_PFD14 = 7182,
    CV_IA64_PFD15 = 7183,
    CV_IA64_PFD16 = 7184,
    CV_IA64_PFD17 = 7185,

    // Performance Monitor Config Registers

    CV_IA64_PFC0 = 7424,
    CV_IA64_PFC1 = 7425,
    CV_IA64_PFC2 = 7426,
    CV_IA64_PFC3 = 7427,
    CV_IA64_PFC4 = 7428,
    CV_IA64_PFC5 = 7429,
    CV_IA64_PFC6 = 7430,
    CV_IA64_PFC7 = 7431,
    CV_IA64_PFC8 = 7432,
    CV_IA64_PFC9 = 7433,
    CV_IA64_PFC10 = 7434,
    CV_IA64_PFC11 = 7435,
    CV_IA64_PFC12 = 7436,
    CV_IA64_PFC13 = 7437,
    CV_IA64_PFC14 = 7438,
    CV_IA64_PFC15 = 7439,

    // Instruction Translation Registers

    CV_IA64_TrI0 = 8192,
    CV_IA64_TrI1 = 8193,
    CV_IA64_TrI2 = 8194,
    CV_IA64_TrI3 = 8195,
    CV_IA64_TrI4 = 8196,
    CV_IA64_TrI5 = 8197,
    CV_IA64_TrI6 = 8198,
    CV_IA64_TrI7 = 8199,

    // Data Translation Registers

    CV_IA64_TrD0 = 8320,
    CV_IA64_TrD1 = 8321,
    CV_IA64_TrD2 = 8322,
    CV_IA64_TrD3 = 8323,
    CV_IA64_TrD4 = 8324,
    CV_IA64_TrD5 = 8325,
    CV_IA64_TrD6 = 8326,
    CV_IA64_TrD7 = 8327,

    // Instruction Breakpoint Registers

    CV_IA64_DbI0 = 8448,
    CV_IA64_DbI1 = 8449,
    CV_IA64_DbI2 = 8450,
    CV_IA64_DbI3 = 8451,
    CV_IA64_DbI4 = 8452,
    CV_IA64_DbI5 = 8453,
    CV_IA64_DbI6 = 8454,
    CV_IA64_DbI7 = 8455,

    // Data Breakpoint Registers

    CV_IA64_DbD0 = 8576,
    CV_IA64_DbD1 = 8577,
    CV_IA64_DbD2 = 8578,
    CV_IA64_DbD3 = 8579,
    CV_IA64_DbD4 = 8580,
    CV_IA64_DbD5 = 8581,
    CV_IA64_DbD6 = 8582,
    CV_IA64_DbD7 = 8583,

    //
    // Register set for the TriCore processor.
    //

    CV_TRI_NOREG = CV_REG_NONE,

    // General Purpose Data Registers

    CV_TRI_D0 = 10,
    CV_TRI_D1 = 11,
    CV_TRI_D2 = 12,
    CV_TRI_D3 = 13,
    CV_TRI_D4 = 14,
    CV_TRI_D5 = 15,
    CV_TRI_D6 = 16,
    CV_TRI_D7 = 17,
    CV_TRI_D8 = 18,
    CV_TRI_D9 = 19,
    CV_TRI_D10 = 20,
    CV_TRI_D11 = 21,
    CV_TRI_D12 = 22,
    CV_TRI_D13 = 23,
    CV_TRI_D14 = 24,
    CV_TRI_D15 = 25,

    // General Purpose Address Registers

    CV_TRI_A0 = 26,
    CV_TRI_A1 = 27,
    CV_TRI_A2 = 28,
    CV_TRI_A3 = 29,
    CV_TRI_A4 = 30,
    CV_TRI_A5 = 31,
    CV_TRI_A6 = 32,
    CV_TRI_A7 = 33,
    CV_TRI_A8 = 34,
    CV_TRI_A9 = 35,
    CV_TRI_A10 = 36,
    CV_TRI_A11 = 37,
    CV_TRI_A12 = 38,
    CV_TRI_A13 = 39,
    CV_TRI_A14 = 40,
    CV_TRI_A15 = 41,

    // Extended (64-bit) data registers

    CV_TRI_E0 = 42,
    CV_TRI_E2 = 43,
    CV_TRI_E4 = 44,
    CV_TRI_E6 = 45,
    CV_TRI_E8 = 46,
    CV_TRI_E10 = 47,
    CV_TRI_E12 = 48,
    CV_TRI_E14 = 49,

    // Extended (64-bit) address registers

    CV_TRI_EA0 = 50,
    CV_TRI_EA2 = 51,
    CV_TRI_EA4 = 52,
    CV_TRI_EA6 = 53,
    CV_TRI_EA8 = 54,
    CV_TRI_EA10 = 55,
    CV_TRI_EA12 = 56,
    CV_TRI_EA14 = 57,

    CV_TRI_PSW = 58,
    CV_TRI_PCXI = 59,
    CV_TRI_PC = 60,
    CV_TRI_FCX = 61,
    CV_TRI_LCX = 62,
    CV_TRI_ISP = 63,
    CV_TRI_ICR = 64,
    CV_TRI_BIV = 65,
    CV_TRI_BTV = 66,
    CV_TRI_SYSCON = 67,
    CV_TRI_DPRx_0 = 68,
    CV_TRI_DPRx_1 = 69,
    CV_TRI_DPRx_2 = 70,
    CV_TRI_DPRx_3 = 71,
    CV_TRI_CPRx_0 = 68,
    CV_TRI_CPRx_1 = 69,
    CV_TRI_CPRx_2 = 70,
    CV_TRI_CPRx_3 = 71,
    CV_TRI_DPMx_0 = 68,
    CV_TRI_DPMx_1 = 69,
    CV_TRI_DPMx_2 = 70,
    CV_TRI_DPMx_3 = 71,
    CV_TRI_CPMx_0 = 68,
    CV_TRI_CPMx_1 = 69,
    CV_TRI_CPMx_2 = 70,
    CV_TRI_CPMx_3 = 71,
    CV_TRI_DBGSSR = 72,
    CV_TRI_EXEVT = 73,
    CV_TRI_SWEVT = 74,
    CV_TRI_CREVT = 75,
    CV_TRI_TRnEVT = 76,
    CV_TRI_MMUCON = 77,
    CV_TRI_ASI = 78,
    CV_TRI_TVA = 79,
    CV_TRI_TPA = 80,
    CV_TRI_TPX = 81,
    CV_TRI_TFA = 82,

    //
    // Register set for the AM33 and related processors.
    //

    CV_AM33_NOREG = CV_REG_NONE,

    // "Extended" (general purpose integer) registers
    CV_AM33_E0 = 10,
    CV_AM33_E1 = 11,
    CV_AM33_E2 = 12,
    CV_AM33_E3 = 13,
    CV_AM33_E4 = 14,
    CV_AM33_E5 = 15,
    CV_AM33_E6 = 16,
    CV_AM33_E7 = 17,

    // Address registers
    CV_AM33_A0 = 20,
    CV_AM33_A1 = 21,
    CV_AM33_A2 = 22,
    CV_AM33_A3 = 23,

    // Integer data registers
    CV_AM33_D0 = 30,
    CV_AM33_D1 = 31,
    CV_AM33_D2 = 32,
    CV_AM33_D3 = 33,

    // (Single-precision) floating-point registers
    CV_AM33_FS0 = 40,
    CV_AM33_FS1 = 41,
    CV_AM33_FS2 = 42,
    CV_AM33_FS3 = 43,
    CV_AM33_FS4 = 44,
    CV_AM33_FS5 = 45,
    CV_AM33_FS6 = 46,
    CV_AM33_FS7 = 47,
    CV_AM33_FS8 = 48,
    CV_AM33_FS9 = 49,
    CV_AM33_FS10 = 50,
    CV_AM33_FS11 = 51,
    CV_AM33_FS12 = 52,
    CV_AM33_FS13 = 53,
    CV_AM33_FS14 = 54,
    CV_AM33_FS15 = 55,
    CV_AM33_FS16 = 56,
    CV_AM33_FS17 = 57,
    CV_AM33_FS18 = 58,
    CV_AM33_FS19 = 59,
    CV_AM33_FS20 = 60,
    CV_AM33_FS21 = 61,
    CV_AM33_FS22 = 62,
    CV_AM33_FS23 = 63,
    CV_AM33_FS24 = 64,
    CV_AM33_FS25 = 65,
    CV_AM33_FS26 = 66,
    CV_AM33_FS27 = 67,
    CV_AM33_FS28 = 68,
    CV_AM33_FS29 = 69,
    CV_AM33_FS30 = 70,
    CV_AM33_FS31 = 71,

    // Special purpose registers

    // Stack pointer
    CV_AM33_SP = 80,

    // Program counter
    CV_AM33_PC = 81,

    // Multiply-divide/accumulate registers
    CV_AM33_MDR = 82,
    CV_AM33_MDRQ = 83,
    CV_AM33_MCRH = 84,
    CV_AM33_MCRL = 85,
    CV_AM33_MCVF = 86,

    // CPU status words
    CV_AM33_EPSW = 87,
    CV_AM33_FPCR = 88,

    // Loop buffer registers
    CV_AM33_LIR = 89,
    CV_AM33_LAR = 90,

    //
    // Register set for the Mitsubishi M32R
    //

    CV_M32R_NOREG = CV_REG_NONE,

    CV_M32R_R0 = 10,
    CV_M32R_R1 = 11,
    CV_M32R_R2 = 12,
    CV_M32R_R3 = 13,
    CV_M32R_R4 = 14,
    CV_M32R_R5 = 15,
    CV_M32R_R6 = 16,
    CV_M32R_R7 = 17,
    CV_M32R_R8 = 18,
    CV_M32R_R9 = 19,
    CV_M32R_R10 = 20,
    CV_M32R_R11 = 21,
    CV_M32R_R12 = 22,   // Gloabal Pointer, if used
    CV_M32R_R13 = 23,   // Frame Pointer, if allocated
    CV_M32R_R14 = 24,   // Link Register
    CV_M32R_R15 = 25,   // Stack Pointer
    CV_M32R_PSW = 26,   // Preocessor Status Register
    CV_M32R_CBR = 27,   // Condition Bit Register
    CV_M32R_SPI = 28,   // Interrupt Stack Pointer
    CV_M32R_SPU = 29,   // User Stack Pointer
    CV_M32R_SPO = 30,   // OS Stack Pointer
    CV_M32R_BPC = 31,   // Backup Program Counter
    CV_M32R_ACHI = 32,   // Accumulator High
    CV_M32R_ACLO = 33,   // Accumulator Low
    CV_M32R_PC = 34,   // Program Counter

    //
    // Register set for the SuperH SHMedia processor including compact
    // mode
    //

    // Integer - 64 bit general registers
    CV_SHMEDIA_NOREG = CV_REG_NONE,
    CV_SHMEDIA_R0 = 10,
    CV_SHMEDIA_R1 = 11,
    CV_SHMEDIA_R2 = 12,
    CV_SHMEDIA_R3 = 13,
    CV_SHMEDIA_R4 = 14,
    CV_SHMEDIA_R5 = 15,
    CV_SHMEDIA_R6 = 16,
    CV_SHMEDIA_R7 = 17,
    CV_SHMEDIA_R8 = 18,
    CV_SHMEDIA_R9 = 19,
    CV_SHMEDIA_R10 = 20,
    CV_SHMEDIA_R11 = 21,
    CV_SHMEDIA_R12 = 22,
    CV_SHMEDIA_R13 = 23,
    CV_SHMEDIA_R14 = 24,
    CV_SHMEDIA_R15 = 25,
    CV_SHMEDIA_R16 = 26,
    CV_SHMEDIA_R17 = 27,
    CV_SHMEDIA_R18 = 28,
    CV_SHMEDIA_R19 = 29,
    CV_SHMEDIA_R20 = 30,
    CV_SHMEDIA_R21 = 31,
    CV_SHMEDIA_R22 = 32,
    CV_SHMEDIA_R23 = 33,
    CV_SHMEDIA_R24 = 34,
    CV_SHMEDIA_R25 = 35,
    CV_SHMEDIA_R26 = 36,
    CV_SHMEDIA_R27 = 37,
    CV_SHMEDIA_R28 = 38,
    CV_SHMEDIA_R29 = 39,
    CV_SHMEDIA_R30 = 40,
    CV_SHMEDIA_R31 = 41,
    CV_SHMEDIA_R32 = 42,
    CV_SHMEDIA_R33 = 43,
    CV_SHMEDIA_R34 = 44,
    CV_SHMEDIA_R35 = 45,
    CV_SHMEDIA_R36 = 46,
    CV_SHMEDIA_R37 = 47,
    CV_SHMEDIA_R38 = 48,
    CV_SHMEDIA_R39 = 49,
    CV_SHMEDIA_R40 = 50,
    CV_SHMEDIA_R41 = 51,
    CV_SHMEDIA_R42 = 52,
    CV_SHMEDIA_R43 = 53,
    CV_SHMEDIA_R44 = 54,
    CV_SHMEDIA_R45 = 55,
    CV_SHMEDIA_R46 = 56,
    CV_SHMEDIA_R47 = 57,
    CV_SHMEDIA_R48 = 58,
    CV_SHMEDIA_R49 = 59,
    CV_SHMEDIA_R50 = 60,
    CV_SHMEDIA_R51 = 61,
    CV_SHMEDIA_R52 = 62,
    CV_SHMEDIA_R53 = 63,
    CV_SHMEDIA_R54 = 64,
    CV_SHMEDIA_R55 = 65,
    CV_SHMEDIA_R56 = 66,
    CV_SHMEDIA_R57 = 67,
    CV_SHMEDIA_R58 = 68,
    CV_SHMEDIA_R59 = 69,
    CV_SHMEDIA_R60 = 70,
    CV_SHMEDIA_R61 = 71,
    CV_SHMEDIA_R62 = 72,
    CV_SHMEDIA_R63 = 73,

    // Target Registers - 32 bit
    CV_SHMEDIA_TR0 = 74,
    CV_SHMEDIA_TR1 = 75,
    CV_SHMEDIA_TR2 = 76,
    CV_SHMEDIA_TR3 = 77,
    CV_SHMEDIA_TR4 = 78,
    CV_SHMEDIA_TR5 = 79,
    CV_SHMEDIA_TR6 = 80,
    CV_SHMEDIA_TR7 = 81,
    CV_SHMEDIA_TR8 = 82, // future-proof
    CV_SHMEDIA_TR9 = 83, // future-proof
    CV_SHMEDIA_TR10 = 84, // future-proof
    CV_SHMEDIA_TR11 = 85, // future-proof
    CV_SHMEDIA_TR12 = 86, // future-proof
    CV_SHMEDIA_TR13 = 87, // future-proof
    CV_SHMEDIA_TR14 = 88, // future-proof
    CV_SHMEDIA_TR15 = 89, // future-proof

    // Single - 32 bit fp registers
    CV_SHMEDIA_FR0 = 128,
    CV_SHMEDIA_FR1 = 129,
    CV_SHMEDIA_FR2 = 130,
    CV_SHMEDIA_FR3 = 131,
    CV_SHMEDIA_FR4 = 132,
    CV_SHMEDIA_FR5 = 133,
    CV_SHMEDIA_FR6 = 134,
    CV_SHMEDIA_FR7 = 135,
    CV_SHMEDIA_FR8 = 136,
    CV_SHMEDIA_FR9 = 137,
    CV_SHMEDIA_FR10 = 138,
    CV_SHMEDIA_FR11 = 139,
    CV_SHMEDIA_FR12 = 140,
    CV_SHMEDIA_FR13 = 141,
    CV_SHMEDIA_FR14 = 142,
    CV_SHMEDIA_FR15 = 143,
    CV_SHMEDIA_FR16 = 144,
    CV_SHMEDIA_FR17 = 145,
    CV_SHMEDIA_FR18 = 146,
    CV_SHMEDIA_FR19 = 147,
    CV_SHMEDIA_FR20 = 148,
    CV_SHMEDIA_FR21 = 149,
    CV_SHMEDIA_FR22 = 150,
    CV_SHMEDIA_FR23 = 151,
    CV_SHMEDIA_FR24 = 152,
    CV_SHMEDIA_FR25 = 153,
    CV_SHMEDIA_FR26 = 154,
    CV_SHMEDIA_FR27 = 155,
    CV_SHMEDIA_FR28 = 156,
    CV_SHMEDIA_FR29 = 157,
    CV_SHMEDIA_FR30 = 158,
    CV_SHMEDIA_FR31 = 159,
    CV_SHMEDIA_FR32 = 160,
    CV_SHMEDIA_FR33 = 161,
    CV_SHMEDIA_FR34 = 162,
    CV_SHMEDIA_FR35 = 163,
    CV_SHMEDIA_FR36 = 164,
    CV_SHMEDIA_FR37 = 165,
    CV_SHMEDIA_FR38 = 166,
    CV_SHMEDIA_FR39 = 167,
    CV_SHMEDIA_FR40 = 168,
    CV_SHMEDIA_FR41 = 169,
    CV_SHMEDIA_FR42 = 170,
    CV_SHMEDIA_FR43 = 171,
    CV_SHMEDIA_FR44 = 172,
    CV_SHMEDIA_FR45 = 173,
    CV_SHMEDIA_FR46 = 174,
    CV_SHMEDIA_FR47 = 175,
    CV_SHMEDIA_FR48 = 176,
    CV_SHMEDIA_FR49 = 177,
    CV_SHMEDIA_FR50 = 178,
    CV_SHMEDIA_FR51 = 179,
    CV_SHMEDIA_FR52 = 180,
    CV_SHMEDIA_FR53 = 181,
    CV_SHMEDIA_FR54 = 182,
    CV_SHMEDIA_FR55 = 183,
    CV_SHMEDIA_FR56 = 184,
    CV_SHMEDIA_FR57 = 185,
    CV_SHMEDIA_FR58 = 186,
    CV_SHMEDIA_FR59 = 187,
    CV_SHMEDIA_FR60 = 188,
    CV_SHMEDIA_FR61 = 189,
    CV_SHMEDIA_FR62 = 190,
    CV_SHMEDIA_FR63 = 191,

    // Double - 64 bit synonyms for 32bit fp register pairs
    //          subtract 128 to find first base single register
    CV_SHMEDIA_DR0 = 256,
    CV_SHMEDIA_DR2 = 258,
    CV_SHMEDIA_DR4 = 260,
    CV_SHMEDIA_DR6 = 262,
    CV_SHMEDIA_DR8 = 264,
    CV_SHMEDIA_DR10 = 266,
    CV_SHMEDIA_DR12 = 268,
    CV_SHMEDIA_DR14 = 270,
    CV_SHMEDIA_DR16 = 272,
    CV_SHMEDIA_DR18 = 274,
    CV_SHMEDIA_DR20 = 276,
    CV_SHMEDIA_DR22 = 278,
    CV_SHMEDIA_DR24 = 280,
    CV_SHMEDIA_DR26 = 282,
    CV_SHMEDIA_DR28 = 284,
    CV_SHMEDIA_DR30 = 286,
    CV_SHMEDIA_DR32 = 288,
    CV_SHMEDIA_DR34 = 290,
    CV_SHMEDIA_DR36 = 292,
    CV_SHMEDIA_DR38 = 294,
    CV_SHMEDIA_DR40 = 296,
    CV_SHMEDIA_DR42 = 298,
    CV_SHMEDIA_DR44 = 300,
    CV_SHMEDIA_DR46 = 302,
    CV_SHMEDIA_DR48 = 304,
    CV_SHMEDIA_DR50 = 306,
    CV_SHMEDIA_DR52 = 308,
    CV_SHMEDIA_DR54 = 310,
    CV_SHMEDIA_DR56 = 312,
    CV_SHMEDIA_DR58 = 314,
    CV_SHMEDIA_DR60 = 316,
    CV_SHMEDIA_DR62 = 318,

    // Vector - 128 bit synonyms for 32bit fp register quads
    //          subtract 384 to find first base single register
    CV_SHMEDIA_FV0 = 512,
    CV_SHMEDIA_FV4 = 516,
    CV_SHMEDIA_FV8 = 520,
    CV_SHMEDIA_FV12 = 524,
    CV_SHMEDIA_FV16 = 528,
    CV_SHMEDIA_FV20 = 532,
    CV_SHMEDIA_FV24 = 536,
    CV_SHMEDIA_FV28 = 540,
    CV_SHMEDIA_FV32 = 544,
    CV_SHMEDIA_FV36 = 548,
    CV_SHMEDIA_FV40 = 552,
    CV_SHMEDIA_FV44 = 556,
    CV_SHMEDIA_FV48 = 560,
    CV_SHMEDIA_FV52 = 564,
    CV_SHMEDIA_FV56 = 568,
    CV_SHMEDIA_FV60 = 572,

    // Matrix - 512 bit synonyms for 16 adjacent 32bit fp registers
    //          subtract 896 to find first base single register
    CV_SHMEDIA_MTRX0 = 1024,
    CV_SHMEDIA_MTRX16 = 1040,
    CV_SHMEDIA_MTRX32 = 1056,
    CV_SHMEDIA_MTRX48 = 1072,

    // Control - Implementation defined 64bit control registers
    CV_SHMEDIA_CR0 = 2000,
    CV_SHMEDIA_CR1 = 2001,
    CV_SHMEDIA_CR2 = 2002,
    CV_SHMEDIA_CR3 = 2003,
    CV_SHMEDIA_CR4 = 2004,
    CV_SHMEDIA_CR5 = 2005,
    CV_SHMEDIA_CR6 = 2006,
    CV_SHMEDIA_CR7 = 2007,
    CV_SHMEDIA_CR8 = 2008,
    CV_SHMEDIA_CR9 = 2009,
    CV_SHMEDIA_CR10 = 2010,
    CV_SHMEDIA_CR11 = 2011,
    CV_SHMEDIA_CR12 = 2012,
    CV_SHMEDIA_CR13 = 2013,
    CV_SHMEDIA_CR14 = 2014,
    CV_SHMEDIA_CR15 = 2015,
    CV_SHMEDIA_CR16 = 2016,
    CV_SHMEDIA_CR17 = 2017,
    CV_SHMEDIA_CR18 = 2018,
    CV_SHMEDIA_CR19 = 2019,
    CV_SHMEDIA_CR20 = 2020,
    CV_SHMEDIA_CR21 = 2021,
    CV_SHMEDIA_CR22 = 2022,
    CV_SHMEDIA_CR23 = 2023,
    CV_SHMEDIA_CR24 = 2024,
    CV_SHMEDIA_CR25 = 2025,
    CV_SHMEDIA_CR26 = 2026,
    CV_SHMEDIA_CR27 = 2027,
    CV_SHMEDIA_CR28 = 2028,
    CV_SHMEDIA_CR29 = 2029,
    CV_SHMEDIA_CR30 = 2030,
    CV_SHMEDIA_CR31 = 2031,
    CV_SHMEDIA_CR32 = 2032,
    CV_SHMEDIA_CR33 = 2033,
    CV_SHMEDIA_CR34 = 2034,
    CV_SHMEDIA_CR35 = 2035,
    CV_SHMEDIA_CR36 = 2036,
    CV_SHMEDIA_CR37 = 2037,
    CV_SHMEDIA_CR38 = 2038,
    CV_SHMEDIA_CR39 = 2039,
    CV_SHMEDIA_CR40 = 2040,
    CV_SHMEDIA_CR41 = 2041,
    CV_SHMEDIA_CR42 = 2042,
    CV_SHMEDIA_CR43 = 2043,
    CV_SHMEDIA_CR44 = 2044,
    CV_SHMEDIA_CR45 = 2045,
    CV_SHMEDIA_CR46 = 2046,
    CV_SHMEDIA_CR47 = 2047,
    CV_SHMEDIA_CR48 = 2048,
    CV_SHMEDIA_CR49 = 2049,
    CV_SHMEDIA_CR50 = 2050,
    CV_SHMEDIA_CR51 = 2051,
    CV_SHMEDIA_CR52 = 2052,
    CV_SHMEDIA_CR53 = 2053,
    CV_SHMEDIA_CR54 = 2054,
    CV_SHMEDIA_CR55 = 2055,
    CV_SHMEDIA_CR56 = 2056,
    CV_SHMEDIA_CR57 = 2057,
    CV_SHMEDIA_CR58 = 2058,
    CV_SHMEDIA_CR59 = 2059,
    CV_SHMEDIA_CR60 = 2060,
    CV_SHMEDIA_CR61 = 2061,
    CV_SHMEDIA_CR62 = 2062,
    CV_SHMEDIA_CR63 = 2063,

    CV_SHMEDIA_FPSCR = 2064,

    // Compact mode synonyms
    CV_SHMEDIA_GBR = CV_SHMEDIA_R16,
    CV_SHMEDIA_MACL = 90, // synonym for lower 32bits of media R17
    CV_SHMEDIA_MACH = 91, // synonym for upper 32bits of media R17
    CV_SHMEDIA_PR = CV_SHMEDIA_R18,
    CV_SHMEDIA_T = 92, // synonym for lowest bit of media R19
    CV_SHMEDIA_FPUL = CV_SHMEDIA_FR32,
    CV_SHMEDIA_PC = 93,
    CV_SHMEDIA_SR = CV_SHMEDIA_CR0,

    //
    // AMD64 registers
    //

    CV_AMD64_AL = 1,
    CV_AMD64_CL = 2,
    CV_AMD64_DL = 3,
    CV_AMD64_BL = 4,
    CV_AMD64_AH = 5,
    CV_AMD64_CH = 6,
    CV_AMD64_DH = 7,
    CV_AMD64_BH = 8,
    CV_AMD64_AX = 9,
    CV_AMD64_CX = 10,
    CV_AMD64_DX = 11,
    CV_AMD64_BX = 12,
    CV_AMD64_SP = 13,
    CV_AMD64_BP = 14,
    CV_AMD64_SI = 15,
    CV_AMD64_DI = 16,
    CV_AMD64_EAX = 17,
    CV_AMD64_ECX = 18,
    CV_AMD64_EDX = 19,
    CV_AMD64_EBX = 20,
    CV_AMD64_ESP = 21,
    CV_AMD64_EBP = 22,
    CV_AMD64_ESI = 23,
    CV_AMD64_EDI = 24,
    CV_AMD64_ES = 25,
    CV_AMD64_CS = 26,
    CV_AMD64_SS = 27,
    CV_AMD64_DS = 28,
    CV_AMD64_FS = 29,
    CV_AMD64_GS = 30,
    CV_AMD64_FLAGS = 32,
    CV_AMD64_RIP = 33,
    CV_AMD64_EFLAGS = 34,

    // Control registers
    CV_AMD64_CR0 = 80,
    CV_AMD64_CR1 = 81,
    CV_AMD64_CR2 = 82,
    CV_AMD64_CR3 = 83,
    CV_AMD64_CR4 = 84,
    CV_AMD64_CR8 = 88,

    // Debug registers
    CV_AMD64_DR0 = 90,
    CV_AMD64_DR1 = 91,
    CV_AMD64_DR2 = 92,
    CV_AMD64_DR3 = 93,
    CV_AMD64_DR4 = 94,
    CV_AMD64_DR5 = 95,
    CV_AMD64_DR6 = 96,
    CV_AMD64_DR7 = 97,
    CV_AMD64_DR8 = 98,
    CV_AMD64_DR9 = 99,
    CV_AMD64_DR10 = 100,
    CV_AMD64_DR11 = 101,
    CV_AMD64_DR12 = 102,
    CV_AMD64_DR13 = 103,
    CV_AMD64_DR14 = 104,
    CV_AMD64_DR15 = 105,

    CV_AMD64_GDTR = 110,
    CV_AMD64_GDTL = 111,
    CV_AMD64_IDTR = 112,
    CV_AMD64_IDTL = 113,
    CV_AMD64_LDTR = 114,
    CV_AMD64_TR = 115,

    CV_AMD64_ST0 = 128,
    CV_AMD64_ST1 = 129,
    CV_AMD64_ST2 = 130,
    CV_AMD64_ST3 = 131,
    CV_AMD64_ST4 = 132,
    CV_AMD64_ST5 = 133,
    CV_AMD64_ST6 = 134,
    CV_AMD64_ST7 = 135,
    CV_AMD64_CTRL = 136,
    CV_AMD64_STAT = 137,
    CV_AMD64_TAG = 138,
    CV_AMD64_FPIP = 139,
    CV_AMD64_FPCS = 140,
    CV_AMD64_FPDO = 141,
    CV_AMD64_FPDS = 142,
    CV_AMD64_ISEM = 143,
    CV_AMD64_FPEIP = 144,
    CV_AMD64_FPEDO = 145,

    CV_AMD64_MM0 = 146,
    CV_AMD64_MM1 = 147,
    CV_AMD64_MM2 = 148,
    CV_AMD64_MM3 = 149,
    CV_AMD64_MM4 = 150,
    CV_AMD64_MM5 = 151,
    CV_AMD64_MM6 = 152,
    CV_AMD64_MM7 = 153,

    CV_AMD64_XMM0 = 154,   // KATMAI registers
    CV_AMD64_XMM1 = 155,
    CV_AMD64_XMM2 = 156,
    CV_AMD64_XMM3 = 157,
    CV_AMD64_XMM4 = 158,
    CV_AMD64_XMM5 = 159,
    CV_AMD64_XMM6 = 160,
    CV_AMD64_XMM7 = 161,

    CV_AMD64_XMM0_0 = 162,   // KATMAI sub-registers
    CV_AMD64_XMM0_1 = 163,
    CV_AMD64_XMM0_2 = 164,
    CV_AMD64_XMM0_3 = 165,
    CV_AMD64_XMM1_0 = 166,
    CV_AMD64_XMM1_1 = 167,
    CV_AMD64_XMM1_2 = 168,
    CV_AMD64_XMM1_3 = 169,
    CV_AMD64_XMM2_0 = 170,
    CV_AMD64_XMM2_1 = 171,
    CV_AMD64_XMM2_2 = 172,
    CV_AMD64_XMM2_3 = 173,
    CV_AMD64_XMM3_0 = 174,
    CV_AMD64_XMM3_1 = 175,
    CV_AMD64_XMM3_2 = 176,
    CV_AMD64_XMM3_3 = 177,
    CV_AMD64_XMM4_0 = 178,
    CV_AMD64_XMM4_1 = 179,
    CV_AMD64_XMM4_2 = 180,
    CV_AMD64_XMM4_3 = 181,
    CV_AMD64_XMM5_0 = 182,
    CV_AMD64_XMM5_1 = 183,
    CV_AMD64_XMM5_2 = 184,
    CV_AMD64_XMM5_3 = 185,
    CV_AMD64_XMM6_0 = 186,
    CV_AMD64_XMM6_1 = 187,
    CV_AMD64_XMM6_2 = 188,
    CV_AMD64_XMM6_3 = 189,
    CV_AMD64_XMM7_0 = 190,
    CV_AMD64_XMM7_1 = 191,
    CV_AMD64_XMM7_2 = 192,
    CV_AMD64_XMM7_3 = 193,

    CV_AMD64_XMM0L = 194,
    CV_AMD64_XMM1L = 195,
    CV_AMD64_XMM2L = 196,
    CV_AMD64_XMM3L = 197,
    CV_AMD64_XMM4L = 198,
    CV_AMD64_XMM5L = 199,
    CV_AMD64_XMM6L = 200,
    CV_AMD64_XMM7L = 201,

    CV_AMD64_XMM0H = 202,
    CV_AMD64_XMM1H = 203,
    CV_AMD64_XMM2H = 204,
    CV_AMD64_XMM3H = 205,
    CV_AMD64_XMM4H = 206,
    CV_AMD64_XMM5H = 207,
    CV_AMD64_XMM6H = 208,
    CV_AMD64_XMM7H = 209,

    CV_AMD64_MXCSR = 211,   // XMM status register

    CV_AMD64_EMM0L = 220,   // XMM sub-registers (WNI integer)
    CV_AMD64_EMM1L = 221,
    CV_AMD64_EMM2L = 222,
    CV_AMD64_EMM3L = 223,
    CV_AMD64_EMM4L = 224,
    CV_AMD64_EMM5L = 225,
    CV_AMD64_EMM6L = 226,
    CV_AMD64_EMM7L = 227,

    CV_AMD64_EMM0H = 228,
    CV_AMD64_EMM1H = 229,
    CV_AMD64_EMM2H = 230,
    CV_AMD64_EMM3H = 231,
    CV_AMD64_EMM4H = 232,
    CV_AMD64_EMM5H = 233,
    CV_AMD64_EMM6H = 234,
    CV_AMD64_EMM7H = 235,

    // do not change the order of these regs, first one must be even too
    CV_AMD64_MM00 = 236,
    CV_AMD64_MM01 = 237,
    CV_AMD64_MM10 = 238,
    CV_AMD64_MM11 = 239,
    CV_AMD64_MM20 = 240,
    CV_AMD64_MM21 = 241,
    CV_AMD64_MM30 = 242,
    CV_AMD64_MM31 = 243,
    CV_AMD64_MM40 = 244,
    CV_AMD64_MM41 = 245,
    CV_AMD64_MM50 = 246,
    CV_AMD64_MM51 = 247,
    CV_AMD64_MM60 = 248,
    CV_AMD64_MM61 = 249,
    CV_AMD64_MM70 = 250,
    CV_AMD64_MM71 = 251,

    // Extended KATMAI registers
    CV_AMD64_XMM8 = 252,   // KATMAI registers
    CV_AMD64_XMM9 = 253,
    CV_AMD64_XMM10 = 254,
    CV_AMD64_XMM11 = 255,
    CV_AMD64_XMM12 = 256,
    CV_AMD64_XMM13 = 257,
    CV_AMD64_XMM14 = 258,
    CV_AMD64_XMM15 = 259,

    CV_AMD64_XMM8_0 = 260,   // KATMAI sub-registers
    CV_AMD64_XMM8_1 = 261,
    CV_AMD64_XMM8_2 = 262,
    CV_AMD64_XMM8_3 = 263,
    CV_AMD64_XMM9_0 = 264,
    CV_AMD64_XMM9_1 = 265,
    CV_AMD64_XMM9_2 = 266,
    CV_AMD64_XMM9_3 = 267,
    CV_AMD64_XMM10_0 = 268,
    CV_AMD64_XMM10_1 = 269,
    CV_AMD64_XMM10_2 = 270,
    CV_AMD64_XMM10_3 = 271,
    CV_AMD64_XMM11_0 = 272,
    CV_AMD64_XMM11_1 = 273,
    CV_AMD64_XMM11_2 = 274,
    CV_AMD64_XMM11_3 = 275,
    CV_AMD64_XMM12_0 = 276,
    CV_AMD64_XMM12_1 = 277,
    CV_AMD64_XMM12_2 = 278,
    CV_AMD64_XMM12_3 = 279,
    CV_AMD64_XMM13_0 = 280,
    CV_AMD64_XMM13_1 = 281,
    CV_AMD64_XMM13_2 = 282,
    CV_AMD64_XMM13_3 = 283,
    CV_AMD64_XMM14_0 = 284,
    CV_AMD64_XMM14_1 = 285,
    CV_AMD64_XMM14_2 = 286,
    CV_AMD64_XMM14_3 = 287,
    CV_AMD64_XMM15_0 = 288,
    CV_AMD64_XMM15_1 = 289,
    CV_AMD64_XMM15_2 = 290,
    CV_AMD64_XMM15_3 = 291,

    CV_AMD64_XMM8L = 292,
    CV_AMD64_XMM9L = 293,
    CV_AMD64_XMM10L = 294,
    CV_AMD64_XMM11L = 295,
    CV_AMD64_XMM12L = 296,
    CV_AMD64_XMM13L = 297,
    CV_AMD64_XMM14L = 298,
    CV_AMD64_XMM15L = 299,

    CV_AMD64_XMM8H = 300,
    CV_AMD64_XMM9H = 301,
    CV_AMD64_XMM10H = 302,
    CV_AMD64_XMM11H = 303,
    CV_AMD64_XMM12H = 304,
    CV_AMD64_XMM13H = 305,
    CV_AMD64_XMM14H = 306,
    CV_AMD64_XMM15H = 307,

    CV_AMD64_EMM8L = 308,   // XMM sub-registers (WNI integer)
    CV_AMD64_EMM9L = 309,
    CV_AMD64_EMM10L = 310,
    CV_AMD64_EMM11L = 311,
    CV_AMD64_EMM12L = 312,
    CV_AMD64_EMM13L = 313,
    CV_AMD64_EMM14L = 314,
    CV_AMD64_EMM15L = 315,

    CV_AMD64_EMM8H = 316,
    CV_AMD64_EMM9H = 317,
    CV_AMD64_EMM10H = 318,
    CV_AMD64_EMM11H = 319,
    CV_AMD64_EMM12H = 320,
    CV_AMD64_EMM13H = 321,
    CV_AMD64_EMM14H = 322,
    CV_AMD64_EMM15H = 323,

    // Low byte forms of some standard registers
    CV_AMD64_SIL = 324,
    CV_AMD64_DIL = 325,
    CV_AMD64_BPL = 326,
    CV_AMD64_SPL = 327,

    // 64-bit regular registers
    CV_AMD64_RAX = 328,
    CV_AMD64_RBX = 329,
    CV_AMD64_RCX = 330,
    CV_AMD64_RDX = 331,
    CV_AMD64_RSI = 332,
    CV_AMD64_RDI = 333,
    CV_AMD64_RBP = 334,
    CV_AMD64_RSP = 335,

    // 64-bit integer registers with 8-, 16-, and 32-bit forms (B, W, and D)
    CV_AMD64_R8 = 336,
    CV_AMD64_R9 = 337,
    CV_AMD64_R10 = 338,
    CV_AMD64_R11 = 339,
    CV_AMD64_R12 = 340,
    CV_AMD64_R13 = 341,
    CV_AMD64_R14 = 342,
    CV_AMD64_R15 = 343,

    CV_AMD64_R8B = 344,
    CV_AMD64_R9B = 345,
    CV_AMD64_R10B = 346,
    CV_AMD64_R11B = 347,
    CV_AMD64_R12B = 348,
    CV_AMD64_R13B = 349,
    CV_AMD64_R14B = 350,
    CV_AMD64_R15B = 351,

    CV_AMD64_R8W = 352,
    CV_AMD64_R9W = 353,
    CV_AMD64_R10W = 354,
    CV_AMD64_R11W = 355,
    CV_AMD64_R12W = 356,
    CV_AMD64_R13W = 357,
    CV_AMD64_R14W = 358,
    CV_AMD64_R15W = 359,

    CV_AMD64_R8D = 360,
    CV_AMD64_R9D = 361,
    CV_AMD64_R10D = 362,
    CV_AMD64_R11D = 363,
    CV_AMD64_R12D = 364,
    CV_AMD64_R13D = 365,
    CV_AMD64_R14D = 366,
    CV_AMD64_R15D = 367,

    // AVX registers 256 bits
    CV_AMD64_YMM0 = 368,
    CV_AMD64_YMM1 = 369,
    CV_AMD64_YMM2 = 370,
    CV_AMD64_YMM3 = 371,
    CV_AMD64_YMM4 = 372,
    CV_AMD64_YMM5 = 373,
    CV_AMD64_YMM6 = 374,
    CV_AMD64_YMM7 = 375,
    CV_AMD64_YMM8 = 376,
    CV_AMD64_YMM9 = 377,
    CV_AMD64_YMM10 = 378,
    CV_AMD64_YMM11 = 379,
    CV_AMD64_YMM12 = 380,
    CV_AMD64_YMM13 = 381,
    CV_AMD64_YMM14 = 382,
    CV_AMD64_YMM15 = 383,

    // AVX registers upper 128 bits
    CV_AMD64_YMM0H = 384,
    CV_AMD64_YMM1H = 385,
    CV_AMD64_YMM2H = 386,
    CV_AMD64_YMM3H = 387,
    CV_AMD64_YMM4H = 388,
    CV_AMD64_YMM5H = 389,
    CV_AMD64_YMM6H = 390,
    CV_AMD64_YMM7H = 391,
    CV_AMD64_YMM8H = 392,
    CV_AMD64_YMM9H = 393,
    CV_AMD64_YMM10H = 394,
    CV_AMD64_YMM11H = 395,
    CV_AMD64_YMM12H = 396,
    CV_AMD64_YMM13H = 397,
    CV_AMD64_YMM14H = 398,
    CV_AMD64_YMM15H = 399,

    //Lower/upper 8 bytes of XMM registers.  Unlike CV_AMD64_XMM<regnum><H/L>, these
    //values reprsesent the bit patterns of the registers as 64-bit integers, not
    //the representation of these registers as a double.
    CV_AMD64_XMM0IL = 400,
    CV_AMD64_XMM1IL = 401,
    CV_AMD64_XMM2IL = 402,
    CV_AMD64_XMM3IL = 403,
    CV_AMD64_XMM4IL = 404,
    CV_AMD64_XMM5IL = 405,
    CV_AMD64_XMM6IL = 406,
    CV_AMD64_XMM7IL = 407,
    CV_AMD64_XMM8IL = 408,
    CV_AMD64_XMM9IL = 409,
    CV_AMD64_XMM10IL = 410,
    CV_AMD64_XMM11IL = 411,
    CV_AMD64_XMM12IL = 412,
    CV_AMD64_XMM13IL = 413,
    CV_AMD64_XMM14IL = 414,
    CV_AMD64_XMM15IL = 415,

    CV_AMD64_XMM0IH = 416,
    CV_AMD64_XMM1IH = 417,
    CV_AMD64_XMM2IH = 418,
    CV_AMD64_XMM3IH = 419,
    CV_AMD64_XMM4IH = 420,
    CV_AMD64_XMM5IH = 421,
    CV_AMD64_XMM6IH = 422,
    CV_AMD64_XMM7IH = 423,
    CV_AMD64_XMM8IH = 424,
    CV_AMD64_XMM9IH = 425,
    CV_AMD64_XMM10IH = 426,
    CV_AMD64_XMM11IH = 427,
    CV_AMD64_XMM12IH = 428,
    CV_AMD64_XMM13IH = 429,
    CV_AMD64_XMM14IH = 430,
    CV_AMD64_XMM15IH = 431,

    CV_AMD64_YMM0I0 = 432,        // AVX integer registers
    CV_AMD64_YMM0I1 = 433,
    CV_AMD64_YMM0I2 = 434,
    CV_AMD64_YMM0I3 = 435,
    CV_AMD64_YMM1I0 = 436,
    CV_AMD64_YMM1I1 = 437,
    CV_AMD64_YMM1I2 = 438,
    CV_AMD64_YMM1I3 = 439,
    CV_AMD64_YMM2I0 = 440,
    CV_AMD64_YMM2I1 = 441,
    CV_AMD64_YMM2I2 = 442,
    CV_AMD64_YMM2I3 = 443,
    CV_AMD64_YMM3I0 = 444,
    CV_AMD64_YMM3I1 = 445,
    CV_AMD64_YMM3I2 = 446,
    CV_AMD64_YMM3I3 = 447,
    CV_AMD64_YMM4I0 = 448,
    CV_AMD64_YMM4I1 = 449,
    CV_AMD64_YMM4I2 = 450,
    CV_AMD64_YMM4I3 = 451,
    CV_AMD64_YMM5I0 = 452,
    CV_AMD64_YMM5I1 = 453,
    CV_AMD64_YMM5I2 = 454,
    CV_AMD64_YMM5I3 = 455,
    CV_AMD64_YMM6I0 = 456,
    CV_AMD64_YMM6I1 = 457,
    CV_AMD64_YMM6I2 = 458,
    CV_AMD64_YMM6I3 = 459,
    CV_AMD64_YMM7I0 = 460,
    CV_AMD64_YMM7I1 = 461,
    CV_AMD64_YMM7I2 = 462,
    CV_AMD64_YMM7I3 = 463,
    CV_AMD64_YMM8I0 = 464,
    CV_AMD64_YMM8I1 = 465,
    CV_AMD64_YMM8I2 = 466,
    CV_AMD64_YMM8I3 = 467,
    CV_AMD64_YMM9I0 = 468,
    CV_AMD64_YMM9I1 = 469,
    CV_AMD64_YMM9I2 = 470,
    CV_AMD64_YMM9I3 = 471,
    CV_AMD64_YMM10I0 = 472,
    CV_AMD64_YMM10I1 = 473,
    CV_AMD64_YMM10I2 = 474,
    CV_AMD64_YMM10I3 = 475,
    CV_AMD64_YMM11I0 = 476,
    CV_AMD64_YMM11I1 = 477,
    CV_AMD64_YMM11I2 = 478,
    CV_AMD64_YMM11I3 = 479,
    CV_AMD64_YMM12I0 = 480,
    CV_AMD64_YMM12I1 = 481,
    CV_AMD64_YMM12I2 = 482,
    CV_AMD64_YMM12I3 = 483,
    CV_AMD64_YMM13I0 = 484,
    CV_AMD64_YMM13I1 = 485,
    CV_AMD64_YMM13I2 = 486,
    CV_AMD64_YMM13I3 = 487,
    CV_AMD64_YMM14I0 = 488,
    CV_AMD64_YMM14I1 = 489,
    CV_AMD64_YMM14I2 = 490,
    CV_AMD64_YMM14I3 = 491,
    CV_AMD64_YMM15I0 = 492,
    CV_AMD64_YMM15I1 = 493,
    CV_AMD64_YMM15I2 = 494,
    CV_AMD64_YMM15I3 = 495,

    CV_AMD64_YMM0F0 = 496,        // AVX floating-point single precise registers
    CV_AMD64_YMM0F1 = 497,
    CV_AMD64_YMM0F2 = 498,
    CV_AMD64_YMM0F3 = 499,
    CV_AMD64_YMM0F4 = 500,
    CV_AMD64_YMM0F5 = 501,
    CV_AMD64_YMM0F6 = 502,
    CV_AMD64_YMM0F7 = 503,
    CV_AMD64_YMM1F0 = 504,
    CV_AMD64_YMM1F1 = 505,
    CV_AMD64_YMM1F2 = 506,
    CV_AMD64_YMM1F3 = 507,
    CV_AMD64_YMM1F4 = 508,
    CV_AMD64_YMM1F5 = 509,
    CV_AMD64_YMM1F6 = 510,
    CV_AMD64_YMM1F7 = 511,
    CV_AMD64_YMM2F0 = 512,
    CV_AMD64_YMM2F1 = 513,
    CV_AMD64_YMM2F2 = 514,
    CV_AMD64_YMM2F3 = 515,
    CV_AMD64_YMM2F4 = 516,
    CV_AMD64_YMM2F5 = 517,
    CV_AMD64_YMM2F6 = 518,
    CV_AMD64_YMM2F7 = 519,
    CV_AMD64_YMM3F0 = 520,
    CV_AMD64_YMM3F1 = 521,
    CV_AMD64_YMM3F2 = 522,
    CV_AMD64_YMM3F3 = 523,
    CV_AMD64_YMM3F4 = 524,
    CV_AMD64_YMM3F5 = 525,
    CV_AMD64_YMM3F6 = 526,
    CV_AMD64_YMM3F7 = 527,
    CV_AMD64_YMM4F0 = 528,
    CV_AMD64_YMM4F1 = 529,
    CV_AMD64_YMM4F2 = 530,
    CV_AMD64_YMM4F3 = 531,
    CV_AMD64_YMM4F4 = 532,
    CV_AMD64_YMM4F5 = 533,
    CV_AMD64_YMM4F6 = 534,
    CV_AMD64_YMM4F7 = 535,
    CV_AMD64_YMM5F0 = 536,
    CV_AMD64_YMM5F1 = 537,
    CV_AMD64_YMM5F2 = 538,
    CV_AMD64_YMM5F3 = 539,
    CV_AMD64_YMM5F4 = 540,
    CV_AMD64_YMM5F5 = 541,
    CV_AMD64_YMM5F6 = 542,
    CV_AMD64_YMM5F7 = 543,
    CV_AMD64_YMM6F0 = 544,
    CV_AMD64_YMM6F1 = 545,
    CV_AMD64_YMM6F2 = 546,
    CV_AMD64_YMM6F3 = 547,
    CV_AMD64_YMM6F4 = 548,
    CV_AMD64_YMM6F5 = 549,
    CV_AMD64_YMM6F6 = 550,
    CV_AMD64_YMM6F7 = 551,
    CV_AMD64_YMM7F0 = 552,
    CV_AMD64_YMM7F1 = 553,
    CV_AMD64_YMM7F2 = 554,
    CV_AMD64_YMM7F3 = 555,
    CV_AMD64_YMM7F4 = 556,
    CV_AMD64_YMM7F5 = 557,
    CV_AMD64_YMM7F6 = 558,
    CV_AMD64_YMM7F7 = 559,
    CV_AMD64_YMM8F0 = 560,
    CV_AMD64_YMM8F1 = 561,
    CV_AMD64_YMM8F2 = 562,
    CV_AMD64_YMM8F3 = 563,
    CV_AMD64_YMM8F4 = 564,
    CV_AMD64_YMM8F5 = 565,
    CV_AMD64_YMM8F6 = 566,
    CV_AMD64_YMM8F7 = 567,
    CV_AMD64_YMM9F0 = 568,
    CV_AMD64_YMM9F1 = 569,
    CV_AMD64_YMM9F2 = 570,
    CV_AMD64_YMM9F3 = 571,
    CV_AMD64_YMM9F4 = 572,
    CV_AMD64_YMM9F5 = 573,
    CV_AMD64_YMM9F6 = 574,
    CV_AMD64_YMM9F7 = 575,
    CV_AMD64_YMM10F0 = 576,
    CV_AMD64_YMM10F1 = 577,
    CV_AMD64_YMM10F2 = 578,
    CV_AMD64_YMM10F3 = 579,
    CV_AMD64_YMM10F4 = 580,
    CV_AMD64_YMM10F5 = 581,
    CV_AMD64_YMM10F6 = 582,
    CV_AMD64_YMM10F7 = 583,
    CV_AMD64_YMM11F0 = 584,
    CV_AMD64_YMM11F1 = 585,
    CV_AMD64_YMM11F2 = 586,
    CV_AMD64_YMM11F3 = 587,
    CV_AMD64_YMM11F4 = 588,
    CV_AMD64_YMM11F5 = 589,
    CV_AMD64_YMM11F6 = 590,
    CV_AMD64_YMM11F7 = 591,
    CV_AMD64_YMM12F0 = 592,
    CV_AMD64_YMM12F1 = 593,
    CV_AMD64_YMM12F2 = 594,
    CV_AMD64_YMM12F3 = 595,
    CV_AMD64_YMM12F4 = 596,
    CV_AMD64_YMM12F5 = 597,
    CV_AMD64_YMM12F6 = 598,
    CV_AMD64_YMM12F7 = 599,
    CV_AMD64_YMM13F0 = 600,
    CV_AMD64_YMM13F1 = 601,
    CV_AMD64_YMM13F2 = 602,
    CV_AMD64_YMM13F3 = 603,
    CV_AMD64_YMM13F4 = 604,
    CV_AMD64_YMM13F5 = 605,
    CV_AMD64_YMM13F6 = 606,
    CV_AMD64_YMM13F7 = 607,
    CV_AMD64_YMM14F0 = 608,
    CV_AMD64_YMM14F1 = 609,
    CV_AMD64_YMM14F2 = 610,
    CV_AMD64_YMM14F3 = 611,
    CV_AMD64_YMM14F4 = 612,
    CV_AMD64_YMM14F5 = 613,
    CV_AMD64_YMM14F6 = 614,
    CV_AMD64_YMM14F7 = 615,
    CV_AMD64_YMM15F0 = 616,
    CV_AMD64_YMM15F1 = 617,
    CV_AMD64_YMM15F2 = 618,
    CV_AMD64_YMM15F3 = 619,
    CV_AMD64_YMM15F4 = 620,
    CV_AMD64_YMM15F5 = 621,
    CV_AMD64_YMM15F6 = 622,
    CV_AMD64_YMM15F7 = 623,

    CV_AMD64_YMM0D0 = 624,        // AVX floating-point double precise registers
    CV_AMD64_YMM0D1 = 625,
    CV_AMD64_YMM0D2 = 626,
    CV_AMD64_YMM0D3 = 627,
    CV_AMD64_YMM1D0 = 628,
    CV_AMD64_YMM1D1 = 629,
    CV_AMD64_YMM1D2 = 630,
    CV_AMD64_YMM1D3 = 631,
    CV_AMD64_YMM2D0 = 632,
    CV_AMD64_YMM2D1 = 633,
    CV_AMD64_YMM2D2 = 634,
    CV_AMD64_YMM2D3 = 635,
    CV_AMD64_YMM3D0 = 636,
    CV_AMD64_YMM3D1 = 637,
    CV_AMD64_YMM3D2 = 638,
    CV_AMD64_YMM3D3 = 639,
    CV_AMD64_YMM4D0 = 640,
    CV_AMD64_YMM4D1 = 641,
    CV_AMD64_YMM4D2 = 642,
    CV_AMD64_YMM4D3 = 643,
    CV_AMD64_YMM5D0 = 644,
    CV_AMD64_YMM5D1 = 645,
    CV_AMD64_YMM5D2 = 646,
    CV_AMD64_YMM5D3 = 647,
    CV_AMD64_YMM6D0 = 648,
    CV_AMD64_YMM6D1 = 649,
    CV_AMD64_YMM6D2 = 650,
    CV_AMD64_YMM6D3 = 651,
    CV_AMD64_YMM7D0 = 652,
    CV_AMD64_YMM7D1 = 653,
    CV_AMD64_YMM7D2 = 654,
    CV_AMD64_YMM7D3 = 655,
    CV_AMD64_YMM8D0 = 656,
    CV_AMD64_YMM8D1 = 657,
    CV_AMD64_YMM8D2 = 658,
    CV_AMD64_YMM8D3 = 659,
    CV_AMD64_YMM9D0 = 660,
    CV_AMD64_YMM9D1 = 661,
    CV_AMD64_YMM9D2 = 662,
    CV_AMD64_YMM9D3 = 663,
    CV_AMD64_YMM10D0 = 664,
    CV_AMD64_YMM10D1 = 665,
    CV_AMD64_YMM10D2 = 666,
    CV_AMD64_YMM10D3 = 667,
    CV_AMD64_YMM11D0 = 668,
    CV_AMD64_YMM11D1 = 669,
    CV_AMD64_YMM11D2 = 670,
    CV_AMD64_YMM11D3 = 671,
    CV_AMD64_YMM12D0 = 672,
    CV_AMD64_YMM12D1 = 673,
    CV_AMD64_YMM12D2 = 674,
    CV_AMD64_YMM12D3 = 675,
    CV_AMD64_YMM13D0 = 676,
    CV_AMD64_YMM13D1 = 677,
    CV_AMD64_YMM13D2 = 678,
    CV_AMD64_YMM13D3 = 679,
    CV_AMD64_YMM14D0 = 680,
    CV_AMD64_YMM14D1 = 681,
    CV_AMD64_YMM14D2 = 682,
    CV_AMD64_YMM14D3 = 683,
    CV_AMD64_YMM15D0 = 684,
    CV_AMD64_YMM15D1 = 685,
    CV_AMD64_YMM15D2 = 686,
    CV_AMD64_YMM15D3 = 687


    // Note:  Next set of platform registers need to go into a new enum...
    // this one is above 44K now.

} CV_HREG_e;

typedef enum CV_HLSLREG_e {
    CV_HLSLREG_TEMP = 0,
    CV_HLSLREG_INPUT = 1,
    CV_HLSLREG_OUTPUT = 2,
    CV_HLSLREG_INDEXABLE_TEMP = 3,
    CV_HLSLREG_IMMEDIATE32 = 4,
    CV_HLSLREG_IMMEDIATE64 = 5,
    CV_HLSLREG_SAMPLER = 6,
    CV_HLSLREG_RESOURCE = 7,
    CV_HLSLREG_CONSTANT_BUFFER = 8,
    CV_HLSLREG_IMMEDIATE_CONSTANT_BUFFER = 9,
    CV_HLSLREG_LABEL = 10,
    CV_HLSLREG_INPUT_PRIMITIVEID = 11,
    CV_HLSLREG_OUTPUT_DEPTH = 12,
    CV_HLSLREG_NULL = 13,
    CV_HLSLREG_RASTERIZER = 14,
    CV_HLSLREG_OUTPUT_COVERAGE_MASK = 15,
    CV_HLSLREG_STREAM = 16,
    CV_HLSLREG_FUNCTION_BODY = 17,
    CV_HLSLREG_FUNCTION_TABLE = 18,
    CV_HLSLREG_INTERFACE = 19,
    CV_HLSLREG_FUNCTION_INPUT = 20,
    CV_HLSLREG_FUNCTION_OUTPUT = 21,
    CV_HLSLREG_OUTPUT_CONTROL_POINT_ID = 22,
    CV_HLSLREG_INPUT_FORK_INSTANCE_ID = 23,
    CV_HLSLREG_INPUT_JOIN_INSTANCE_ID = 24,
    CV_HLSLREG_INPUT_CONTROL_POINT = 25,
    CV_HLSLREG_OUTPUT_CONTROL_POINT = 26,
    CV_HLSLREG_INPUT_PATCH_CONSTANT = 27,
    CV_HLSLREG_INPUT_DOMAIN_POINT = 28,
    CV_HLSLREG_THIS_POINTER = 29,
    CV_HLSLREG_UNORDERED_ACCESS_VIEW = 30,
    CV_HLSLREG_THREAD_GROUP_SHARED_MEMORY = 31,
    CV_HLSLREG_INPUT_THREAD_ID = 32,
    CV_HLSLREG_INPUT_THREAD_GROUP_ID = 33,
    CV_HLSLREG_INPUT_THREAD_ID_IN_GROUP = 34,
    CV_HLSLREG_INPUT_COVERAGE_MASK = 35,
    CV_HLSLREG_INPUT_THREAD_ID_IN_GROUP_FLATTENED = 36,
    CV_HLSLREG_INPUT_GS_INSTANCE_ID = 37,
    CV_HLSLREG_OUTPUT_DEPTH_GREATER_EQUAL = 38,
    CV_HLSLREG_OUTPUT_DEPTH_LESS_EQUAL = 39,
    CV_HLSLREG_CYCLE_COUNTER = 40,
} CV_HLSLREG_e;

enum StackFrameTypeEnum
{
    FrameTypeFPO,                   // Frame pointer omitted, FPO info available
    FrameTypeTrap,                  // Kernel Trap frame
    FrameTypeTSS,                   // Kernel Trap frame
    FrameTypeStandard,              // Standard EBP stackframe
    FrameTypeFrameData,             // Frame pointer omitted, FrameData info available

    FrameTypeUnknown = -1,          // Frame which does not have any debug info
};

enum MemoryTypeEnum
{
    MemTypeCode,                    // Read only code memory
    MemTypeData,                    // Read only data/stack memory
    MemTypeStack,                   // Read only stack memory
    MemTypeCodeOnHeap,              // Read only memory for code generated on heap by runtime

    MemTypeAny = -1,
};

typedef enum CV_HLSLMemorySpace_e
{
    // HLSL specific memory spaces

    CV_HLSL_MEMSPACE_DATA = 0x00,
    CV_HLSL_MEMSPACE_SAMPLER = 0x01,
    CV_HLSL_MEMSPACE_RESOURCE = 0x02,
    CV_HLSL_MEMSPACE_RWRESOURCE = 0x03,

    CV_HLSL_MEMSPACE_MAX = 0x0F,
} CV_HLSLMemorySpace_e;

#endif


#ifndef _CV_INFO_INCLUDED
#define _CV_INFO_INCLUDED

#ifdef  __cplusplus
#pragma warning ( disable: 4200 )
#endif

#ifndef __INLINE
#ifdef  __cplusplus
#define __INLINE inline
#else
#define __INLINE __inline
#endif
#endif

#pragma pack ( push, 1 )
typedef unsigned long   CV_uoff32_t;
typedef          long   CV_off32_t;
typedef unsigned short  CV_uoff16_t;
typedef          short  CV_off16_t;
typedef unsigned short  CV_typ16_t;
typedef unsigned long   CV_typ_t;
typedef unsigned long   CV_pubsymflag_t;    // must be same as CV_typ_t.
typedef unsigned short  _2BYTEPAD;
typedef unsigned long   CV_tkn_t;

#if !defined (CV_ZEROLEN)
#define CV_ZEROLEN
#endif

#if !defined (FLOAT10)
#if defined(_M_I86)                    // 16 bit x86 supporting long double
typedef long double FLOAT10;
#else                                  // 32 bit w/o long double support
typedef struct FLOAT10
{
    char b[10];
} FLOAT10;
#endif
#endif


#define CV_SIGNATURE_C6         0L  // Actual signature is >64K
#define CV_SIGNATURE_C7         1L  // First explicit signature
#define CV_SIGNATURE_C11        2L  // C11 (vc5.x) 32-bit types
#define CV_SIGNATURE_C13        4L  // C13 (vc7.x) zero terminated names
#define CV_SIGNATURE_RESERVED   5L  // All signatures from 5 to 64K are reserved

#define CV_MAXOFFSET   0xffffffff

#ifndef GUID_DEFINED
#define GUID_DEFINED

typedef struct _GUID {          // size is 16
    unsigned long   Data1;
    unsigned short  Data2;
    unsigned short  Data3;
    unsigned char   Data4[8];
} GUID;

#endif // !GUID_DEFINED

typedef GUID            SIG70;      // new to 7.0 are 16-byte guid-like signatures
typedef SIG70 *         PSIG70;
typedef const SIG70 *   PCSIG70;



/**     CodeView Symbol and Type OMF type information is broken up into two
 *      ranges.  Type indices less than 0x1000 describe type information
 *      that is frequently used.  Type indices above 0x1000 are used to
 *      describe more complex features such as functions, arrays and
 *      structures.
 */




/**     Primitive types have predefined meaning that is encoded in the
 *      values of the various bit fields in the value.
 *
 *      A CodeView primitive type is defined as:
 *
 *      1 1
 *      1 089  7654  3  210
 *      r mode type  r  sub
 *
 *      Where
 *          mode is the pointer mode
 *          type is a type indicator
 *          sub  is a subtype enumeration
 *          r    is a reserved field
 *
 *      See Microsoft Symbol and Type OMF (Version 4.0) for more
 *      information.
 */


#define CV_MMASK        0x700       // mode mask
#define CV_TMASK        0x0f0       // type mask

// can we use the reserved bit ??
#define CV_SMASK        0x00f       // subtype mask

#define CV_MSHIFT       8           // primitive mode right shift count
#define CV_TSHIFT       4           // primitive type right shift count
#define CV_SSHIFT       0           // primitive subtype right shift count

// macros to extract primitive mode, type and size

#define CV_MODE(typ)    (((typ) & CV_MMASK) >> CV_MSHIFT)
#define CV_TYPE(typ)    (((typ) & CV_TMASK) >> CV_TSHIFT)
#define CV_SUBT(typ)    (((typ) & CV_SMASK) >> CV_SSHIFT)

// macros to insert new primitive mode, type and size

#define CV_NEWMODE(typ, nm)     ((CV_typ_t)(((typ) & ~CV_MMASK) | ((nm) << CV_MSHIFT)))
#define CV_NEWTYPE(typ, nt)     (((typ) & ~CV_TMASK) | ((nt) << CV_TSHIFT))
#define CV_NEWSUBT(typ, ns)     (((typ) & ~CV_SMASK) | ((ns) << CV_SSHIFT))



//     pointer mode enumeration values

typedef enum CV_prmode_e {
    CV_TM_DIRECT = 0,       // mode is not a pointer
    CV_TM_NPTR   = 1,       // mode is a near pointer
    CV_TM_FPTR   = 2,       // mode is a far pointer
    CV_TM_HPTR   = 3,       // mode is a huge pointer
    CV_TM_NPTR32 = 4,       // mode is a 32 bit near pointer
    CV_TM_FPTR32 = 5,       // mode is a 32 bit far pointer
    CV_TM_NPTR64 = 6,       // mode is a 64 bit near pointer
    CV_TM_NPTR128 = 7,      // mode is a 128 bit near pointer
} CV_prmode_e;




//      type enumeration values


typedef enum CV_type_e {
    CV_SPECIAL      = 0x00,         // special type size values
    CV_SIGNED       = 0x01,         // signed integral size values
    CV_UNSIGNED     = 0x02,         // unsigned integral size values
    CV_BOOLEAN      = 0x03,         // Boolean size values
    CV_REAL         = 0x04,         // real number size values
    CV_COMPLEX      = 0x05,         // complex number size values
    CV_SPECIAL2     = 0x06,         // second set of special types
    CV_INT          = 0x07,         // integral (int) values
    CV_CVRESERVED   = 0x0f,
} CV_type_e;




//      subtype enumeration values for CV_SPECIAL


typedef enum CV_special_e {
    CV_SP_NOTYPE    = 0x00,
    CV_SP_ABS       = 0x01,
    CV_SP_SEGMENT   = 0x02,
    CV_SP_VOID      = 0x03,
    CV_SP_CURRENCY  = 0x04,
    CV_SP_NBASICSTR = 0x05,
    CV_SP_FBASICSTR = 0x06,
    CV_SP_NOTTRANS  = 0x07,
    CV_SP_HRESULT   = 0x08,
} CV_special_e;




//      subtype enumeration values for CV_SPECIAL2


typedef enum CV_special2_e {
    CV_S2_BIT       = 0x00,
    CV_S2_PASCHAR   = 0x01,         // Pascal CHAR
    CV_S2_BOOL32FF  = 0x02,         // 32-bit BOOL where true is 0xffffffff
} CV_special2_e;





//      subtype enumeration values for CV_SIGNED, CV_UNSIGNED and CV_BOOLEAN


typedef enum CV_integral_e {
    CV_IN_1BYTE     = 0x00,
    CV_IN_2BYTE     = 0x01,
    CV_IN_4BYTE     = 0x02,
    CV_IN_8BYTE     = 0x03,
    CV_IN_16BYTE    = 0x04
} CV_integral_e;





//      subtype enumeration values for CV_REAL and CV_COMPLEX


typedef enum CV_real_e {
    CV_RC_REAL32    = 0x00,
    CV_RC_REAL64    = 0x01,
    CV_RC_REAL80    = 0x02,
    CV_RC_REAL128   = 0x03,
    CV_RC_REAL48    = 0x04,
    CV_RC_REAL32PP  = 0x05,   // 32-bit partial precision real
    CV_RC_REAL16    = 0x06,
} CV_real_e;




//      subtype enumeration values for CV_INT (really int)


typedef enum CV_int_e {
    CV_RI_CHAR      = 0x00,
    CV_RI_INT1      = 0x00,
    CV_RI_WCHAR     = 0x01,
    CV_RI_UINT1     = 0x01,
    CV_RI_INT2      = 0x02,
    CV_RI_UINT2     = 0x03,
    CV_RI_INT4      = 0x04,
    CV_RI_UINT4     = 0x05,
    CV_RI_INT8      = 0x06,
    CV_RI_UINT8     = 0x07,
    CV_RI_INT16     = 0x08,
    CV_RI_UINT16    = 0x09,
    CV_RI_CHAR16    = 0x0a,  // char16_t
    CV_RI_CHAR32    = 0x0b,  // char32_t
} CV_int_e;



// macros to check the type of a primitive

#define CV_TYP_IS_DIRECT(typ)   (CV_MODE(typ) == CV_TM_DIRECT)
#define CV_TYP_IS_PTR(typ)      (CV_MODE(typ) != CV_TM_DIRECT)
#define CV_TYP_IS_NPTR(typ)     (CV_MODE(typ) == CV_TM_NPTR)
#define CV_TYP_IS_FPTR(typ)     (CV_MODE(typ) == CV_TM_FPTR)
#define CV_TYP_IS_HPTR(typ)     (CV_MODE(typ) == CV_TM_HPTR)
#define CV_TYP_IS_NPTR32(typ)   (CV_MODE(typ) == CV_TM_NPTR32)
#define CV_TYP_IS_FPTR32(typ)   (CV_MODE(typ) == CV_TM_FPTR32)

#define CV_TYP_IS_SIGNED(typ)   (((CV_TYPE(typ) == CV_SIGNED) && CV_TYP_IS_DIRECT(typ)) || \
                                 (typ == T_INT1)  || \
                                 (typ == T_INT2)  || \
                                 (typ == T_INT4)  || \
                                 (typ == T_INT8)  || \
                                 (typ == T_INT16) || \
                                 (typ == T_RCHAR))

#define CV_TYP_IS_UNSIGNED(typ) (((CV_TYPE(typ) == CV_UNSIGNED) && CV_TYP_IS_DIRECT(typ)) || \
                                 (typ == T_UINT1) || \
                                 (typ == T_UINT2) || \
                                 (typ == T_UINT4) || \
                                 (typ == T_UINT8) || \
                                 (typ == T_UINT16))

#define CV_TYP_IS_REAL(typ)     ((CV_TYPE(typ) == CV_REAL)  && CV_TYP_IS_DIRECT(typ))

#define CV_FIRST_NONPRIM 0x1000
#define CV_IS_PRIMITIVE(typ)    ((typ) < CV_FIRST_NONPRIM)
#define CV_TYP_IS_COMPLEX(typ)  ((CV_TYPE(typ) == CV_COMPLEX)   && CV_TYP_IS_DIRECT(typ))
#define CV_IS_INTERNAL_PTR(typ) (CV_IS_PRIMITIVE(typ) && \
                                 CV_TYPE(typ) == CV_CVRESERVED && \
                                 CV_TYP_IS_PTR(typ))






// selected values for type_index - for a more complete definition, see
// Microsoft Symbol and Type OMF document




//      Special Types

typedef enum TYPE_ENUM_e {
//      Special Types

    T_NOTYPE        = 0x0000,   // uncharacterized type (no type)
    T_ABS           = 0x0001,   // absolute symbol
    T_SEGMENT       = 0x0002,   // segment type
    T_VOID          = 0x0003,   // void
    T_HRESULT       = 0x0008,   // OLE/COM HRESULT
    T_32PHRESULT    = 0x0408,   // OLE/COM HRESULT __ptr32 *
    T_64PHRESULT    = 0x0608,   // OLE/COM HRESULT __ptr64 *

    T_PVOID         = 0x0103,   // near pointer to void
    T_PFVOID        = 0x0203,   // far pointer to void
    T_PHVOID        = 0x0303,   // huge pointer to void
    T_32PVOID       = 0x0403,   // 32 bit pointer to void
    T_32PFVOID      = 0x0503,   // 16:32 pointer to void
    T_64PVOID       = 0x0603,   // 64 bit pointer to void
    T_CURRENCY      = 0x0004,   // BASIC 8 byte currency value
    T_NBASICSTR     = 0x0005,   // Near BASIC string
    T_FBASICSTR     = 0x0006,   // Far BASIC string
    T_NOTTRANS      = 0x0007,   // type not translated by cvpack
    T_BIT           = 0x0060,   // bit
    T_PASCHAR       = 0x0061,   // Pascal CHAR
    T_BOOL32FF      = 0x0062,   // 32-bit BOOL where true is 0xffffffff


//      Character types

    T_CHAR          = 0x0010,   // 8 bit signed
    T_PCHAR         = 0x0110,   // 16 bit pointer to 8 bit signed
    T_PFCHAR        = 0x0210,   // 16:16 far pointer to 8 bit signed
    T_PHCHAR        = 0x0310,   // 16:16 huge pointer to 8 bit signed
    T_32PCHAR       = 0x0410,   // 32 bit pointer to 8 bit signed
    T_32PFCHAR      = 0x0510,   // 16:32 pointer to 8 bit signed
    T_64PCHAR       = 0x0610,   // 64 bit pointer to 8 bit signed

    T_UCHAR         = 0x0020,   // 8 bit unsigned
    T_PUCHAR        = 0x0120,   // 16 bit pointer to 8 bit unsigned
    T_PFUCHAR       = 0x0220,   // 16:16 far pointer to 8 bit unsigned
    T_PHUCHAR       = 0x0320,   // 16:16 huge pointer to 8 bit unsigned
    T_32PUCHAR      = 0x0420,   // 32 bit pointer to 8 bit unsigned
    T_32PFUCHAR     = 0x0520,   // 16:32 pointer to 8 bit unsigned
    T_64PUCHAR      = 0x0620,   // 64 bit pointer to 8 bit unsigned


//      really a character types

    T_RCHAR         = 0x0070,   // really a char
    T_PRCHAR        = 0x0170,   // 16 bit pointer to a real char
    T_PFRCHAR       = 0x0270,   // 16:16 far pointer to a real char
    T_PHRCHAR       = 0x0370,   // 16:16 huge pointer to a real char
    T_32PRCHAR      = 0x0470,   // 32 bit pointer to a real char
    T_32PFRCHAR     = 0x0570,   // 16:32 pointer to a real char
    T_64PRCHAR      = 0x0670,   // 64 bit pointer to a real char


//      really a wide character types

    T_WCHAR         = 0x0071,   // wide char
    T_PWCHAR        = 0x0171,   // 16 bit pointer to a wide char
    T_PFWCHAR       = 0x0271,   // 16:16 far pointer to a wide char
    T_PHWCHAR       = 0x0371,   // 16:16 huge pointer to a wide char
    T_32PWCHAR      = 0x0471,   // 32 bit pointer to a wide char
    T_32PFWCHAR     = 0x0571,   // 16:32 pointer to a wide char
    T_64PWCHAR      = 0x0671,   // 64 bit pointer to a wide char

//      really a 16-bit unicode char

    T_CHAR16         = 0x007a,   // 16-bit unicode char
    T_PCHAR16        = 0x017a,   // 16 bit pointer to a 16-bit unicode char
    T_PFCHAR16       = 0x027a,   // 16:16 far pointer to a 16-bit unicode char
    T_PHCHAR16       = 0x037a,   // 16:16 huge pointer to a 16-bit unicode char
    T_32PCHAR16      = 0x047a,   // 32 bit pointer to a 16-bit unicode char
    T_32PFCHAR16     = 0x057a,   // 16:32 pointer to a 16-bit unicode char
    T_64PCHAR16      = 0x067a,   // 64 bit pointer to a 16-bit unicode char

//      really a 32-bit unicode char

    T_CHAR32         = 0x007b,   // 32-bit unicode char
    T_PCHAR32        = 0x017b,   // 16 bit pointer to a 32-bit unicode char
    T_PFCHAR32       = 0x027b,   // 16:16 far pointer to a 32-bit unicode char
    T_PHCHAR32       = 0x037b,   // 16:16 huge pointer to a 32-bit unicode char
    T_32PCHAR32      = 0x047b,   // 32 bit pointer to a 32-bit unicode char
    T_32PFCHAR32     = 0x057b,   // 16:32 pointer to a 32-bit unicode char
    T_64PCHAR32      = 0x067b,   // 64 bit pointer to a 32-bit unicode char

//      8 bit int types

    T_INT1          = 0x0068,   // 8 bit signed int
    T_PINT1         = 0x0168,   // 16 bit pointer to 8 bit signed int
    T_PFINT1        = 0x0268,   // 16:16 far pointer to 8 bit signed int
    T_PHINT1        = 0x0368,   // 16:16 huge pointer to 8 bit signed int
    T_32PINT1       = 0x0468,   // 32 bit pointer to 8 bit signed int
    T_32PFINT1      = 0x0568,   // 16:32 pointer to 8 bit signed int
    T_64PINT1       = 0x0668,   // 64 bit pointer to 8 bit signed int

    T_UINT1         = 0x0069,   // 8 bit unsigned int
    T_PUINT1        = 0x0169,   // 16 bit pointer to 8 bit unsigned int
    T_PFUINT1       = 0x0269,   // 16:16 far pointer to 8 bit unsigned int
    T_PHUINT1       = 0x0369,   // 16:16 huge pointer to 8 bit unsigned int
    T_32PUINT1      = 0x0469,   // 32 bit pointer to 8 bit unsigned int
    T_32PFUINT1     = 0x0569,   // 16:32 pointer to 8 bit unsigned int
    T_64PUINT1      = 0x0669,   // 64 bit pointer to 8 bit unsigned int


//      16 bit short types

    T_SHORT         = 0x0011,   // 16 bit signed
    T_PSHORT        = 0x0111,   // 16 bit pointer to 16 bit signed
    T_PFSHORT       = 0x0211,   // 16:16 far pointer to 16 bit signed
    T_PHSHORT       = 0x0311,   // 16:16 huge pointer to 16 bit signed
    T_32PSHORT      = 0x0411,   // 32 bit pointer to 16 bit signed
    T_32PFSHORT     = 0x0511,   // 16:32 pointer to 16 bit signed
    T_64PSHORT      = 0x0611,   // 64 bit pointer to 16 bit signed

    T_USHORT        = 0x0021,   // 16 bit unsigned
    T_PUSHORT       = 0x0121,   // 16 bit pointer to 16 bit unsigned
    T_PFUSHORT      = 0x0221,   // 16:16 far pointer to 16 bit unsigned
    T_PHUSHORT      = 0x0321,   // 16:16 huge pointer to 16 bit unsigned
    T_32PUSHORT     = 0x0421,   // 32 bit pointer to 16 bit unsigned
    T_32PFUSHORT    = 0x0521,   // 16:32 pointer to 16 bit unsigned
    T_64PUSHORT     = 0x0621,   // 64 bit pointer to 16 bit unsigned


//      16 bit int types

    T_INT2          = 0x0072,   // 16 bit signed int
    T_PINT2         = 0x0172,   // 16 bit pointer to 16 bit signed int
    T_PFINT2        = 0x0272,   // 16:16 far pointer to 16 bit signed int
    T_PHINT2        = 0x0372,   // 16:16 huge pointer to 16 bit signed int
    T_32PINT2       = 0x0472,   // 32 bit pointer to 16 bit signed int
    T_32PFINT2      = 0x0572,   // 16:32 pointer to 16 bit signed int
    T_64PINT2       = 0x0672,   // 64 bit pointer to 16 bit signed int

    T_UINT2         = 0x0073,   // 16 bit unsigned int
    T_PUINT2        = 0x0173,   // 16 bit pointer to 16 bit unsigned int
    T_PFUINT2       = 0x0273,   // 16:16 far pointer to 16 bit unsigned int
    T_PHUINT2       = 0x0373,   // 16:16 huge pointer to 16 bit unsigned int
    T_32PUINT2      = 0x0473,   // 32 bit pointer to 16 bit unsigned int
    T_32PFUINT2     = 0x0573,   // 16:32 pointer to 16 bit unsigned int
    T_64PUINT2      = 0x0673,   // 64 bit pointer to 16 bit unsigned int


//      32 bit long types

    T_LONG          = 0x0012,   // 32 bit signed
    T_ULONG         = 0x0022,   // 32 bit unsigned
    T_PLONG         = 0x0112,   // 16 bit pointer to 32 bit signed
    T_PULONG        = 0x0122,   // 16 bit pointer to 32 bit unsigned
    T_PFLONG        = 0x0212,   // 16:16 far pointer to 32 bit signed
    T_PFULONG       = 0x0222,   // 16:16 far pointer to 32 bit unsigned
    T_PHLONG        = 0x0312,   // 16:16 huge pointer to 32 bit signed
    T_PHULONG       = 0x0322,   // 16:16 huge pointer to 32 bit unsigned

    T_32PLONG       = 0x0412,   // 32 bit pointer to 32 bit signed
    T_32PULONG      = 0x0422,   // 32 bit pointer to 32 bit unsigned
    T_32PFLONG      = 0x0512,   // 16:32 pointer to 32 bit signed
    T_32PFULONG     = 0x0522,   // 16:32 pointer to 32 bit unsigned
    T_64PLONG       = 0x0612,   // 64 bit pointer to 32 bit signed
    T_64PULONG      = 0x0622,   // 64 bit pointer to 32 bit unsigned


//      32 bit int types

    T_INT4          = 0x0074,   // 32 bit signed int
    T_PINT4         = 0x0174,   // 16 bit pointer to 32 bit signed int
    T_PFINT4        = 0x0274,   // 16:16 far pointer to 32 bit signed int
    T_PHINT4        = 0x0374,   // 16:16 huge pointer to 32 bit signed int
    T_32PINT4       = 0x0474,   // 32 bit pointer to 32 bit signed int
    T_32PFINT4      = 0x0574,   // 16:32 pointer to 32 bit signed int
    T_64PINT4       = 0x0674,   // 64 bit pointer to 32 bit signed int

    T_UINT4         = 0x0075,   // 32 bit unsigned int
    T_PUINT4        = 0x0175,   // 16 bit pointer to 32 bit unsigned int
    T_PFUINT4       = 0x0275,   // 16:16 far pointer to 32 bit unsigned int
    T_PHUINT4       = 0x0375,   // 16:16 huge pointer to 32 bit unsigned int
    T_32PUINT4      = 0x0475,   // 32 bit pointer to 32 bit unsigned int
    T_32PFUINT4     = 0x0575,   // 16:32 pointer to 32 bit unsigned int
    T_64PUINT4      = 0x0675,   // 64 bit pointer to 32 bit unsigned int


//      64 bit quad types

    T_QUAD          = 0x0013,   // 64 bit signed
    T_PQUAD         = 0x0113,   // 16 bit pointer to 64 bit signed
    T_PFQUAD        = 0x0213,   // 16:16 far pointer to 64 bit signed
    T_PHQUAD        = 0x0313,   // 16:16 huge pointer to 64 bit signed
    T_32PQUAD       = 0x0413,   // 32 bit pointer to 64 bit signed
    T_32PFQUAD      = 0x0513,   // 16:32 pointer to 64 bit signed
    T_64PQUAD       = 0x0613,   // 64 bit pointer to 64 bit signed

    T_UQUAD         = 0x0023,   // 64 bit unsigned
    T_PUQUAD        = 0x0123,   // 16 bit pointer to 64 bit unsigned
    T_PFUQUAD       = 0x0223,   // 16:16 far pointer to 64 bit unsigned
    T_PHUQUAD       = 0x0323,   // 16:16 huge pointer to 64 bit unsigned
    T_32PUQUAD      = 0x0423,   // 32 bit pointer to 64 bit unsigned
    T_32PFUQUAD     = 0x0523,   // 16:32 pointer to 64 bit unsigned
    T_64PUQUAD      = 0x0623,   // 64 bit pointer to 64 bit unsigned


//      64 bit int types

    T_INT8          = 0x0076,   // 64 bit signed int
    T_PINT8         = 0x0176,   // 16 bit pointer to 64 bit signed int
    T_PFINT8        = 0x0276,   // 16:16 far pointer to 64 bit signed int
    T_PHINT8        = 0x0376,   // 16:16 huge pointer to 64 bit signed int
    T_32PINT8       = 0x0476,   // 32 bit pointer to 64 bit signed int
    T_32PFINT8      = 0x0576,   // 16:32 pointer to 64 bit signed int
    T_64PINT8       = 0x0676,   // 64 bit pointer to 64 bit signed int

    T_UINT8         = 0x0077,   // 64 bit unsigned int
    T_PUINT8        = 0x0177,   // 16 bit pointer to 64 bit unsigned int
    T_PFUINT8       = 0x0277,   // 16:16 far pointer to 64 bit unsigned int
    T_PHUINT8       = 0x0377,   // 16:16 huge pointer to 64 bit unsigned int
    T_32PUINT8      = 0x0477,   // 32 bit pointer to 64 bit unsigned int
    T_32PFUINT8     = 0x0577,   // 16:32 pointer to 64 bit unsigned int
    T_64PUINT8      = 0x0677,   // 64 bit pointer to 64 bit unsigned int


//      128 bit octet types

    T_OCT           = 0x0014,   // 128 bit signed
    T_POCT          = 0x0114,   // 16 bit pointer to 128 bit signed
    T_PFOCT         = 0x0214,   // 16:16 far pointer to 128 bit signed
    T_PHOCT         = 0x0314,   // 16:16 huge pointer to 128 bit signed
    T_32POCT        = 0x0414,   // 32 bit pointer to 128 bit signed
    T_32PFOCT       = 0x0514,   // 16:32 pointer to 128 bit signed
    T_64POCT        = 0x0614,   // 64 bit pointer to 128 bit signed

    T_UOCT          = 0x0024,   // 128 bit unsigned
    T_PUOCT         = 0x0124,   // 16 bit pointer to 128 bit unsigned
    T_PFUOCT        = 0x0224,   // 16:16 far pointer to 128 bit unsigned
    T_PHUOCT        = 0x0324,   // 16:16 huge pointer to 128 bit unsigned
    T_32PUOCT       = 0x0424,   // 32 bit pointer to 128 bit unsigned
    T_32PFUOCT      = 0x0524,   // 16:32 pointer to 128 bit unsigned
    T_64PUOCT       = 0x0624,   // 64 bit pointer to 128 bit unsigned


//      128 bit int types

    T_INT16         = 0x0078,   // 128 bit signed int
    T_PINT16        = 0x0178,   // 16 bit pointer to 128 bit signed int
    T_PFINT16       = 0x0278,   // 16:16 far pointer to 128 bit signed int
    T_PHINT16       = 0x0378,   // 16:16 huge pointer to 128 bit signed int
    T_32PINT16      = 0x0478,   // 32 bit pointer to 128 bit signed int
    T_32PFINT16     = 0x0578,   // 16:32 pointer to 128 bit signed int
    T_64PINT16      = 0x0678,   // 64 bit pointer to 128 bit signed int

    T_UINT16        = 0x0079,   // 128 bit unsigned int
    T_PUINT16       = 0x0179,   // 16 bit pointer to 128 bit unsigned int
    T_PFUINT16      = 0x0279,   // 16:16 far pointer to 128 bit unsigned int
    T_PHUINT16      = 0x0379,   // 16:16 huge pointer to 128 bit unsigned int
    T_32PUINT16     = 0x0479,   // 32 bit pointer to 128 bit unsigned int
    T_32PFUINT16    = 0x0579,   // 16:32 pointer to 128 bit unsigned int
    T_64PUINT16     = 0x0679,   // 64 bit pointer to 128 bit unsigned int


//      16 bit real types

    T_REAL16        = 0x0046,   // 16 bit real
    T_PREAL16       = 0x0146,   // 16 bit pointer to 16 bit real
    T_PFREAL16      = 0x0246,   // 16:16 far pointer to 16 bit real
    T_PHREAL16      = 0x0346,   // 16:16 huge pointer to 16 bit real
    T_32PREAL16     = 0x0446,   // 32 bit pointer to 16 bit real
    T_32PFREAL16    = 0x0546,   // 16:32 pointer to 16 bit real
    T_64PREAL16     = 0x0646,   // 64 bit pointer to 16 bit real


//      32 bit real types

    T_REAL32        = 0x0040,   // 32 bit real
    T_PREAL32       = 0x0140,   // 16 bit pointer to 32 bit real
    T_PFREAL32      = 0x0240,   // 16:16 far pointer to 32 bit real
    T_PHREAL32      = 0x0340,   // 16:16 huge pointer to 32 bit real
    T_32PREAL32     = 0x0440,   // 32 bit pointer to 32 bit real
    T_32PFREAL32    = 0x0540,   // 16:32 pointer to 32 bit real
    T_64PREAL32     = 0x0640,   // 64 bit pointer to 32 bit real


//      32 bit partial-precision real types

    T_REAL32PP      = 0x0045,   // 32 bit PP real
    T_PREAL32PP     = 0x0145,   // 16 bit pointer to 32 bit PP real
    T_PFREAL32PP    = 0x0245,   // 16:16 far pointer to 32 bit PP real
    T_PHREAL32PP    = 0x0345,   // 16:16 huge pointer to 32 bit PP real
    T_32PREAL32PP   = 0x0445,   // 32 bit pointer to 32 bit PP real
    T_32PFREAL32PP  = 0x0545,   // 16:32 pointer to 32 bit PP real
    T_64PREAL32PP   = 0x0645,   // 64 bit pointer to 32 bit PP real


//      48 bit real types

    T_REAL48        = 0x0044,   // 48 bit real
    T_PREAL48       = 0x0144,   // 16 bit pointer to 48 bit real
    T_PFREAL48      = 0x0244,   // 16:16 far pointer to 48 bit real
    T_PHREAL48      = 0x0344,   // 16:16 huge pointer to 48 bit real
    T_32PREAL48     = 0x0444,   // 32 bit pointer to 48 bit real
    T_32PFREAL48    = 0x0544,   // 16:32 pointer to 48 bit real
    T_64PREAL48     = 0x0644,   // 64 bit pointer to 48 bit real


//      64 bit real types

    T_REAL64        = 0x0041,   // 64 bit real
    T_PREAL64       = 0x0141,   // 16 bit pointer to 64 bit real
    T_PFREAL64      = 0x0241,   // 16:16 far pointer to 64 bit real
    T_PHREAL64      = 0x0341,   // 16:16 huge pointer to 64 bit real
    T_32PREAL64     = 0x0441,   // 32 bit pointer to 64 bit real
    T_32PFREAL64    = 0x0541,   // 16:32 pointer to 64 bit real
    T_64PREAL64     = 0x0641,   // 64 bit pointer to 64 bit real


//      80 bit real types

    T_REAL80        = 0x0042,   // 80 bit real
    T_PREAL80       = 0x0142,   // 16 bit pointer to 80 bit real
    T_PFREAL80      = 0x0242,   // 16:16 far pointer to 80 bit real
    T_PHREAL80      = 0x0342,   // 16:16 huge pointer to 80 bit real
    T_32PREAL80     = 0x0442,   // 32 bit pointer to 80 bit real
    T_32PFREAL80    = 0x0542,   // 16:32 pointer to 80 bit real
    T_64PREAL80     = 0x0642,   // 64 bit pointer to 80 bit real


//      128 bit real types

    T_REAL128       = 0x0043,   // 128 bit real
    T_PREAL128      = 0x0143,   // 16 bit pointer to 128 bit real
    T_PFREAL128     = 0x0243,   // 16:16 far pointer to 128 bit real
    T_PHREAL128     = 0x0343,   // 16:16 huge pointer to 128 bit real
    T_32PREAL128    = 0x0443,   // 32 bit pointer to 128 bit real
    T_32PFREAL128   = 0x0543,   // 16:32 pointer to 128 bit real
    T_64PREAL128    = 0x0643,   // 64 bit pointer to 128 bit real


//      32 bit complex types

    T_CPLX32        = 0x0050,   // 32 bit complex
    T_PCPLX32       = 0x0150,   // 16 bit pointer to 32 bit complex
    T_PFCPLX32      = 0x0250,   // 16:16 far pointer to 32 bit complex
    T_PHCPLX32      = 0x0350,   // 16:16 huge pointer to 32 bit complex
    T_32PCPLX32     = 0x0450,   // 32 bit pointer to 32 bit complex
    T_32PFCPLX32    = 0x0550,   // 16:32 pointer to 32 bit complex
    T_64PCPLX32     = 0x0650,   // 64 bit pointer to 32 bit complex


//      64 bit complex types

    T_CPLX64        = 0x0051,   // 64 bit complex
    T_PCPLX64       = 0x0151,   // 16 bit pointer to 64 bit complex
    T_PFCPLX64      = 0x0251,   // 16:16 far pointer to 64 bit complex
    T_PHCPLX64      = 0x0351,   // 16:16 huge pointer to 64 bit complex
    T_32PCPLX64     = 0x0451,   // 32 bit pointer to 64 bit complex
    T_32PFCPLX64    = 0x0551,   // 16:32 pointer to 64 bit complex
    T_64PCPLX64     = 0x0651,   // 64 bit pointer to 64 bit complex


//      80 bit complex types

    T_CPLX80        = 0x0052,   // 80 bit complex
    T_PCPLX80       = 0x0152,   // 16 bit pointer to 80 bit complex
    T_PFCPLX80      = 0x0252,   // 16:16 far pointer to 80 bit complex
    T_PHCPLX80      = 0x0352,   // 16:16 huge pointer to 80 bit complex
    T_32PCPLX80     = 0x0452,   // 32 bit pointer to 80 bit complex
    T_32PFCPLX80    = 0x0552,   // 16:32 pointer to 80 bit complex
    T_64PCPLX80     = 0x0652,   // 64 bit pointer to 80 bit complex


//      128 bit complex types

    T_CPLX128       = 0x0053,   // 128 bit complex
    T_PCPLX128      = 0x0153,   // 16 bit pointer to 128 bit complex
    T_PFCPLX128     = 0x0253,   // 16:16 far pointer to 128 bit complex
    T_PHCPLX128     = 0x0353,   // 16:16 huge pointer to 128 bit real
    T_32PCPLX128    = 0x0453,   // 32 bit pointer to 128 bit complex
    T_32PFCPLX128   = 0x0553,   // 16:32 pointer to 128 bit complex
    T_64PCPLX128    = 0x0653,   // 64 bit pointer to 128 bit complex


//      boolean types

    T_BOOL08        = 0x0030,   // 8 bit boolean
    T_PBOOL08       = 0x0130,   // 16 bit pointer to  8 bit boolean
    T_PFBOOL08      = 0x0230,   // 16:16 far pointer to  8 bit boolean
    T_PHBOOL08      = 0x0330,   // 16:16 huge pointer to  8 bit boolean
    T_32PBOOL08     = 0x0430,   // 32 bit pointer to 8 bit boolean
    T_32PFBOOL08    = 0x0530,   // 16:32 pointer to 8 bit boolean
    T_64PBOOL08     = 0x0630,   // 64 bit pointer to 8 bit boolean

    T_BOOL16        = 0x0031,   // 16 bit boolean
    T_PBOOL16       = 0x0131,   // 16 bit pointer to 16 bit boolean
    T_PFBOOL16      = 0x0231,   // 16:16 far pointer to 16 bit boolean
    T_PHBOOL16      = 0x0331,   // 16:16 huge pointer to 16 bit boolean
    T_32PBOOL16     = 0x0431,   // 32 bit pointer to 18 bit boolean
    T_32PFBOOL16    = 0x0531,   // 16:32 pointer to 16 bit boolean
    T_64PBOOL16     = 0x0631,   // 64 bit pointer to 18 bit boolean

    T_BOOL32        = 0x0032,   // 32 bit boolean
    T_PBOOL32       = 0x0132,   // 16 bit pointer to 32 bit boolean
    T_PFBOOL32      = 0x0232,   // 16:16 far pointer to 32 bit boolean
    T_PHBOOL32      = 0x0332,   // 16:16 huge pointer to 32 bit boolean
    T_32PBOOL32     = 0x0432,   // 32 bit pointer to 32 bit boolean
    T_32PFBOOL32    = 0x0532,   // 16:32 pointer to 32 bit boolean
    T_64PBOOL32     = 0x0632,   // 64 bit pointer to 32 bit boolean

    T_BOOL64        = 0x0033,   // 64 bit boolean
    T_PBOOL64       = 0x0133,   // 16 bit pointer to 64 bit boolean
    T_PFBOOL64      = 0x0233,   // 16:16 far pointer to 64 bit boolean
    T_PHBOOL64      = 0x0333,   // 16:16 huge pointer to 64 bit boolean
    T_32PBOOL64     = 0x0433,   // 32 bit pointer to 64 bit boolean
    T_32PFBOOL64    = 0x0533,   // 16:32 pointer to 64 bit boolean
    T_64PBOOL64     = 0x0633,   // 64 bit pointer to 64 bit boolean


//      ???

    T_NCVPTR        = 0x01f0,   // CV Internal type for created near pointers
    T_FCVPTR        = 0x02f0,   // CV Internal type for created far pointers
    T_HCVPTR        = 0x03f0,   // CV Internal type for created huge pointers
    T_32NCVPTR      = 0x04f0,   // CV Internal type for created near 32-bit pointers
    T_32FCVPTR      = 0x05f0,   // CV Internal type for created far 32-bit pointers
    T_64NCVPTR      = 0x06f0,   // CV Internal type for created near 64-bit pointers

} TYPE_ENUM_e;

/**     No leaf index can have a value of 0x0000.  The leaf indices are
 *      separated into ranges depending upon the use of the type record.
 *      The second range is for the type records that are directly referenced
 *      in symbols. The first range is for type records that are not
 *      referenced by symbols but instead are referenced by other type
 *      records.  All type records must have a starting leaf index in these
 *      first two ranges.  The third range of leaf indices are used to build
 *      up complex lists such as the field list of a class type record.  No
 *      type record can begin with one of the leaf indices. The fourth ranges
 *      of type indices are used to represent numeric data in a symbol or
 *      type record. These leaf indices are greater than 0x8000.  At the
 *      point that type or symbol processor is expecting a numeric field, the
 *      next two bytes in the type record are examined.  If the value is less
 *      than 0x8000, then the two bytes contain the numeric value.  If the
 *      value is greater than 0x8000, then the data follows the leaf index in
 *      a format specified by the leaf index. The final range of leaf indices
 *      are used to force alignment of subfields within a complex type record..
 */


typedef enum LEAF_ENUM_e {
    // leaf indices starting records but referenced from symbol records

    LF_MODIFIER_16t     = 0x0001,
    LF_POINTER_16t      = 0x0002,
    LF_ARRAY_16t        = 0x0003,
    LF_CLASS_16t        = 0x0004,
    LF_STRUCTURE_16t    = 0x0005,
    LF_UNION_16t        = 0x0006,
    LF_ENUM_16t         = 0x0007,
    LF_PROCEDURE_16t    = 0x0008,
    LF_MFUNCTION_16t    = 0x0009,
    LF_VTSHAPE          = 0x000a,
    LF_COBOL0_16t       = 0x000b,
    LF_COBOL1           = 0x000c,
    LF_BARRAY_16t       = 0x000d,
    LF_LABEL            = 0x000e,
    LF_NULL             = 0x000f,
    LF_NOTTRAN          = 0x0010,
    LF_DIMARRAY_16t     = 0x0011,
    LF_VFTPATH_16t      = 0x0012,
    LF_PRECOMP_16t      = 0x0013,       // not referenced from symbol
    LF_ENDPRECOMP       = 0x0014,       // not referenced from symbol
    LF_OEM_16t          = 0x0015,       // oem definable type string
    LF_TYPESERVER_ST    = 0x0016,       // not referenced from symbol

    // leaf indices starting records but referenced only from type records

    LF_SKIP_16t         = 0x0200,
    LF_ARGLIST_16t      = 0x0201,
    LF_DEFARG_16t       = 0x0202,
    LF_LIST             = 0x0203,
    LF_FIELDLIST_16t    = 0x0204,
    LF_DERIVED_16t      = 0x0205,
    LF_BITFIELD_16t     = 0x0206,
    LF_METHODLIST_16t   = 0x0207,
    LF_DIMCONU_16t      = 0x0208,
    LF_DIMCONLU_16t     = 0x0209,
    LF_DIMVARU_16t      = 0x020a,
    LF_DIMVARLU_16t     = 0x020b,
    LF_REFSYM           = 0x020c,

    LF_BCLASS_16t       = 0x0400,
    LF_VBCLASS_16t      = 0x0401,
    LF_IVBCLASS_16t     = 0x0402,
    LF_ENUMERATE_ST     = 0x0403,
    LF_FRIENDFCN_16t    = 0x0404,
    LF_INDEX_16t        = 0x0405,
    LF_MEMBER_16t       = 0x0406,
    LF_STMEMBER_16t     = 0x0407,
    LF_METHOD_16t       = 0x0408,
    LF_NESTTYPE_16t     = 0x0409,
    LF_VFUNCTAB_16t     = 0x040a,
    LF_FRIENDCLS_16t    = 0x040b,
    LF_ONEMETHOD_16t    = 0x040c,
    LF_VFUNCOFF_16t     = 0x040d,

// 32-bit type index versions of leaves, all have the 0x1000 bit set
//
    LF_TI16_MAX         = 0x1000,

    LF_MODIFIER         = 0x1001,
    LF_POINTER          = 0x1002,
    LF_ARRAY_ST         = 0x1003,
    LF_CLASS_ST         = 0x1004,
    LF_STRUCTURE_ST     = 0x1005,
    LF_UNION_ST         = 0x1006,
    LF_ENUM_ST          = 0x1007,
    LF_PROCEDURE        = 0x1008,
    LF_MFUNCTION        = 0x1009,
    LF_COBOL0           = 0x100a,
    LF_BARRAY           = 0x100b,
    LF_DIMARRAY_ST      = 0x100c,
    LF_VFTPATH          = 0x100d,
    LF_PRECOMP_ST       = 0x100e,       // not referenced from symbol
    LF_OEM              = 0x100f,       // oem definable type string
    LF_ALIAS_ST         = 0x1010,       // alias (typedef) type
    LF_OEM2             = 0x1011,       // oem definable type string

    // leaf indices starting records but referenced only from type records

    LF_SKIP             = 0x1200,
    LF_ARGLIST          = 0x1201,
    LF_DEFARG_ST        = 0x1202,
    LF_FIELDLIST        = 0x1203,
    LF_DERIVED          = 0x1204,
    LF_BITFIELD         = 0x1205,
    LF_METHODLIST       = 0x1206,
    LF_DIMCONU          = 0x1207,
    LF_DIMCONLU         = 0x1208,
    LF_DIMVARU          = 0x1209,
    LF_DIMVARLU         = 0x120a,

    LF_BCLASS           = 0x1400,
    LF_VBCLASS          = 0x1401,
    LF_IVBCLASS         = 0x1402,
    LF_FRIENDFCN_ST     = 0x1403,
    LF_INDEX            = 0x1404,
    LF_MEMBER_ST        = 0x1405,
    LF_STMEMBER_ST      = 0x1406,
    LF_METHOD_ST        = 0x1407,
    LF_NESTTYPE_ST      = 0x1408,
    LF_VFUNCTAB         = 0x1409,
    LF_FRIENDCLS        = 0x140a,
    LF_ONEMETHOD_ST     = 0x140b,
    LF_VFUNCOFF         = 0x140c,
    LF_NESTTYPEEX_ST    = 0x140d,
    LF_MEMBERMODIFY_ST  = 0x140e,
    LF_MANAGED_ST       = 0x140f,

    // Types w/ SZ names

    LF_ST_MAX           = 0x1500,

    LF_TYPESERVER       = 0x1501,       // not referenced from symbol
    LF_ENUMERATE        = 0x1502,
    LF_ARRAY            = 0x1503,
    LF_CLASS            = 0x1504,
    LF_STRUCTURE        = 0x1505,
    LF_UNION            = 0x1506,
    LF_ENUM             = 0x1507,
    LF_DIMARRAY         = 0x1508,
    LF_PRECOMP          = 0x1509,       // not referenced from symbol
    LF_ALIAS            = 0x150a,       // alias (typedef) type
    LF_DEFARG           = 0x150b,
    LF_FRIENDFCN        = 0x150c,
    LF_MEMBER           = 0x150d,
    LF_STMEMBER         = 0x150e,
    LF_METHOD           = 0x150f,
    LF_NESTTYPE         = 0x1510,
    LF_ONEMETHOD        = 0x1511,
    LF_NESTTYPEEX       = 0x1512,
    LF_MEMBERMODIFY     = 0x1513,
    LF_MANAGED          = 0x1514,
    LF_TYPESERVER2      = 0x1515,

    LF_STRIDED_ARRAY    = 0x1516,    // same as LF_ARRAY, but with stride between adjacent elements
    LF_HLSL             = 0x1517,
    LF_MODIFIER_EX      = 0x1518,
    LF_INTERFACE        = 0x1519,
    LF_BINTERFACE       = 0x151a,
    LF_VECTOR           = 0x151b,
    LF_MATRIX           = 0x151c,

    LF_VFTABLE          = 0x151d,      // a virtual function table
    LF_ENDOFLEAFRECORD  = LF_VFTABLE,

    LF_TYPE_LAST,                    // one greater than the last type record
    LF_TYPE_MAX         = LF_TYPE_LAST - 1,

    LF_FUNC_ID          = 0x1601,    // global func ID
    LF_MFUNC_ID         = 0x1602,    // member func ID
    LF_BUILDINFO        = 0x1603,    // build info: tool, version, command line, src/pdb file
    LF_SUBSTR_LIST      = 0x1604,    // similar to LF_ARGLIST, for list of sub strings
    LF_STRING_ID        = 0x1605,    // string ID

    LF_UDT_SRC_LINE     = 0x1606,    // source and line on where an UDT is defined
                                     // only generated by compiler

    LF_UDT_MOD_SRC_LINE = 0x1607,    // module, source and line on where an UDT is defined
                                     // only generated by linker

    LF_ID_LAST,                      // one greater than the last ID record
    LF_ID_MAX           = LF_ID_LAST - 1,

    LF_NUMERIC          = 0x8000,
    LF_CHAR             = 0x8000,
    LF_SHORT            = 0x8001,
    LF_USHORT           = 0x8002,
    LF_LONG             = 0x8003,
    LF_ULONG            = 0x8004,
    LF_REAL32           = 0x8005,
    LF_REAL64           = 0x8006,
    LF_REAL80           = 0x8007,
    LF_REAL128          = 0x8008,
    LF_QUADWORD         = 0x8009,
    LF_UQUADWORD        = 0x800a,
    LF_REAL48           = 0x800b,
    LF_COMPLEX32        = 0x800c,
    LF_COMPLEX64        = 0x800d,
    LF_COMPLEX80        = 0x800e,
    LF_COMPLEX128       = 0x800f,
    LF_VARSTRING        = 0x8010,

    LF_OCTWORD          = 0x8017,
    LF_UOCTWORD         = 0x8018,

    LF_DECIMAL          = 0x8019,
    LF_DATE             = 0x801a,
    LF_UTF8STRING       = 0x801b,

    LF_REAL16           = 0x801c,
    
    LF_PAD0             = 0xf0,
    LF_PAD1             = 0xf1,
    LF_PAD2             = 0xf2,
    LF_PAD3             = 0xf3,
    LF_PAD4             = 0xf4,
    LF_PAD5             = 0xf5,
    LF_PAD6             = 0xf6,
    LF_PAD7             = 0xf7,
    LF_PAD8             = 0xf8,
    LF_PAD9             = 0xf9,
    LF_PAD10            = 0xfa,
    LF_PAD11            = 0xfb,
    LF_PAD12            = 0xfc,
    LF_PAD13            = 0xfd,
    LF_PAD14            = 0xfe,
    LF_PAD15            = 0xff,

} LEAF_ENUM_e;

// end of leaf indices




//      Type enum for pointer records
//      Pointers can be one of the following types


typedef enum CV_ptrtype_e {
    CV_PTR_NEAR         = 0x00, // 16 bit pointer
    CV_PTR_FAR          = 0x01, // 16:16 far pointer
    CV_PTR_HUGE         = 0x02, // 16:16 huge pointer
    CV_PTR_BASE_SEG     = 0x03, // based on segment
    CV_PTR_BASE_VAL     = 0x04, // based on value of base
    CV_PTR_BASE_SEGVAL  = 0x05, // based on segment value of base
    CV_PTR_BASE_ADDR    = 0x06, // based on address of base
    CV_PTR_BASE_SEGADDR = 0x07, // based on segment address of base
    CV_PTR_BASE_TYPE    = 0x08, // based on type
    CV_PTR_BASE_SELF    = 0x09, // based on self
    CV_PTR_NEAR32       = 0x0a, // 32 bit pointer
    CV_PTR_FAR32        = 0x0b, // 16:32 pointer
    CV_PTR_64           = 0x0c, // 64 bit pointer
    CV_PTR_UNUSEDPTR    = 0x0d  // first unused pointer type
} CV_ptrtype_e;





//      Mode enum for pointers
//      Pointers can have one of the following modes
//
//  To support for l-value and r-value reference, we added CV_PTR_MODE_LVREF
//  and CV_PTR_MODE_RVREF.  CV_PTR_MODE_REF should be removed at some point.
//  We keep it now so that old code that uses it won't be broken.
//  

typedef enum CV_ptrmode_e {
    CV_PTR_MODE_PTR     = 0x00, // "normal" pointer
    CV_PTR_MODE_REF     = 0x01, // "old" reference
    CV_PTR_MODE_LVREF   = 0x01, // l-value reference
    CV_PTR_MODE_PMEM    = 0x02, // pointer to data member
    CV_PTR_MODE_PMFUNC  = 0x03, // pointer to member function
    CV_PTR_MODE_RVREF   = 0x04, // r-value reference
    CV_PTR_MODE_RESERVED= 0x05  // first unused pointer mode
} CV_ptrmode_e;


//      enumeration for pointer-to-member types

typedef enum CV_pmtype_e {
    CV_PMTYPE_Undef     = 0x00, // not specified (pre VC8)
    CV_PMTYPE_D_Single  = 0x01, // member data, single inheritance
    CV_PMTYPE_D_Multiple= 0x02, // member data, multiple inheritance
    CV_PMTYPE_D_Virtual = 0x03, // member data, virtual inheritance
    CV_PMTYPE_D_General = 0x04, // member data, most general
    CV_PMTYPE_F_Single  = 0x05, // member function, single inheritance
    CV_PMTYPE_F_Multiple= 0x06, // member function, multiple inheritance
    CV_PMTYPE_F_Virtual = 0x07, // member function, virtual inheritance
    CV_PMTYPE_F_General = 0x08, // member function, most general
} CV_pmtype_e;

//      enumeration for method properties

typedef enum CV_methodprop_e {
    CV_MTvanilla        = 0x00,
    CV_MTvirtual        = 0x01,
    CV_MTstatic         = 0x02,
    CV_MTfriend         = 0x03,
    CV_MTintro          = 0x04,
    CV_MTpurevirt       = 0x05,
    CV_MTpureintro      = 0x06
} CV_methodprop_e;




//      enumeration for virtual shape table entries

typedef enum CV_VTS_desc_e {
    CV_VTS_near         = 0x00,
    CV_VTS_far          = 0x01,
    CV_VTS_thin         = 0x02,
    CV_VTS_outer        = 0x03,
    CV_VTS_meta         = 0x04,
    CV_VTS_near32       = 0x05,
    CV_VTS_far32        = 0x06,
    CV_VTS_unused       = 0x07
} CV_VTS_desc_e;




//      enumeration for LF_LABEL address modes

typedef enum CV_LABEL_TYPE_e {
    CV_LABEL_NEAR = 0,       // near return
    CV_LABEL_FAR  = 4        // far return
} CV_LABEL_TYPE_e;



//      enumeration for LF_MODIFIER values


typedef struct CV_modifier_t {
    unsigned short  MOD_const       :1;
    unsigned short  MOD_volatile    :1;
    unsigned short  MOD_unaligned   :1;
    unsigned short  MOD_unused      :13;
} CV_modifier_t;




//  enumeration for HFA kinds

typedef enum CV_HFA_e {
   CV_HFA_none   =  0,
   CV_HFA_float  =  1,
   CV_HFA_double =  2,
   CV_HFA_other  =  3
} CV_HFA_e;

//  enumeration for MoCOM UDT kinds

typedef enum CV_MOCOM_UDT_e {
    CV_MOCOM_UDT_none      = 0,
    CV_MOCOM_UDT_ref       = 1,
    CV_MOCOM_UDT_value     = 2,
    CV_MOCOM_UDT_interface = 3
} CV_MOCOM_UDT_e;

//  bit field structure describing class/struct/union/enum properties

typedef struct CV_prop_t {
    unsigned short  packed      :1;     // true if structure is packed
    unsigned short  ctor        :1;     // true if constructors or destructors present
    unsigned short  ovlops      :1;     // true if overloaded operators present
    unsigned short  isnested    :1;     // true if this is a nested class
    unsigned short  cnested     :1;     // true if this class contains nested types
    unsigned short  opassign    :1;     // true if overloaded assignment (=)
    unsigned short  opcast      :1;     // true if casting methods
    unsigned short  fwdref      :1;     // true if forward reference (incomplete defn)
    unsigned short  scoped      :1;     // scoped definition
    unsigned short  hasuniquename :1;   // true if there is a decorated name following the regular name
    unsigned short  sealed      :1;     // true if class cannot be used as a base class
    unsigned short  hfa         :2;     // CV_HFA_e
    unsigned short  intrinsic   :1;     // true if class is an intrinsic type (e.g. __m128d)
    unsigned short  mocom       :2;     // CV_MOCOM_UDT_e
} CV_prop_t;




//  class field attribute

typedef struct CV_fldattr_t {
    unsigned short  access      :2;     // access protection CV_access_t
    unsigned short  mprop       :3;     // method properties CV_methodprop_t
    unsigned short  pseudo      :1;     // compiler generated fcn and does not exist
    unsigned short  noinherit   :1;     // true if class cannot be inherited
    unsigned short  noconstruct :1;     // true if class cannot be constructed
    unsigned short  compgenx    :1;     // compiler generated fcn and does exist
    unsigned short  sealed      :1;     // true if method cannot be overridden
    unsigned short  unused      :6;     // unused
} CV_fldattr_t;


//  function flags

typedef struct CV_funcattr_t {
    unsigned char  cxxreturnudt :1;  // true if C++ style ReturnUDT
    unsigned char  ctor         :1;  // true if func is an instance constructor
    unsigned char  ctorvbase    :1;  // true if func is an instance constructor of a class with virtual bases
    unsigned char  unused       :5;  // unused
} CV_funcattr_t;


//  matrix flags

typedef struct CV_matrixattr_t {
    unsigned char  row_major   :1;   // true if matrix has row-major layout (column-major is default)
    unsigned char  unused      :7;   // unused
} CV_matrixattr_t;


//  Structures to access to the type records


typedef struct TYPTYPE {
    unsigned short  len;
    unsigned short  leaf;
    unsigned char   data[CV_ZEROLEN];
} TYPTYPE;          // general types record

__INLINE char *NextType ( _In_ char * pType) {
    return (pType + ((TYPTYPE *)pType)->len + sizeof(unsigned short));
}

typedef enum CV_PMEMBER {
    CV_PDM16_NONVIRT    = 0x00, // 16:16 data no virtual fcn or base
    CV_PDM16_VFCN       = 0x01, // 16:16 data with virtual functions
    CV_PDM16_VBASE      = 0x02, // 16:16 data with virtual bases
    CV_PDM32_NVVFCN     = 0x03, // 16:32 data w/wo virtual functions
    CV_PDM32_VBASE      = 0x04, // 16:32 data with virtual bases

    CV_PMF16_NEARNVSA   = 0x05, // 16:16 near method nonvirtual single address point
    CV_PMF16_NEARNVMA   = 0x06, // 16:16 near method nonvirtual multiple address points
    CV_PMF16_NEARVBASE  = 0x07, // 16:16 near method virtual bases
    CV_PMF16_FARNVSA    = 0x08, // 16:16 far method nonvirtual single address point
    CV_PMF16_FARNVMA    = 0x09, // 16:16 far method nonvirtual multiple address points
    CV_PMF16_FARVBASE   = 0x0a, // 16:16 far method virtual bases

    CV_PMF32_NVSA       = 0x0b, // 16:32 method nonvirtual single address point
    CV_PMF32_NVMA       = 0x0c, // 16:32 method nonvirtual multiple address point
    CV_PMF32_VBASE      = 0x0d  // 16:32 method virtual bases
} CV_PMEMBER;



//  memory representation of pointer to member.  These representations are
//  indexed by the enumeration above in the LF_POINTER record




//  representation of a 16:16 pointer to data for a class with no
//  virtual functions or virtual bases


struct CV_PDMR16_NONVIRT {
    CV_off16_t      mdisp;      // displacement to data (NULL = -1)
};




//  representation of a 16:16 pointer to data for a class with virtual
//  functions


struct CV_PMDR16_VFCN {
    CV_off16_t      mdisp;      // displacement to data ( NULL = 0)
};




//  representation of a 16:16 pointer to data for a class with
//  virtual bases


struct CV_PDMR16_VBASE {
    CV_off16_t      mdisp;      // displacement to data
    CV_off16_t      pdisp;      // this pointer displacement to vbptr
    CV_off16_t      vdisp;      // displacement within vbase table
                                // NULL = (,,0xffff)
};




//  representation of a 32 bit pointer to data for a class with
//  or without virtual functions and no virtual bases


struct CV_PDMR32_NVVFCN {
    CV_off32_t      mdisp;      // displacement to data (NULL = 0x80000000)
};




//  representation of a 32 bit pointer to data for a class
//  with virtual bases


struct CV_PDMR32_VBASE {
    CV_off32_t      mdisp;      // displacement to data
    CV_off32_t      pdisp;      // this pointer displacement
    CV_off32_t      vdisp;      // vbase table displacement
                                // NULL = (,,0xffffffff)
};




//  representation of a 16:16 pointer to near member function for a
//  class with no virtual functions or bases and a single address point


struct CV_PMFR16_NEARNVSA {
    CV_uoff16_t     off;        // near address of function (NULL = 0)
};



//  representation of a 16 bit pointer to member functions of a
//  class with no virtual bases and multiple address points


struct CV_PMFR16_NEARNVMA {
    CV_uoff16_t     off;        // offset of function (NULL = 0,x)
    signed short    disp;
};




//  representation of a 16 bit pointer to member function of a
//  class with virtual bases


struct CV_PMFR16_NEARVBASE {
    CV_uoff16_t     off;        // offset of function (NULL = 0,x,x,x)
    CV_off16_t      mdisp;      // displacement to data
    CV_off16_t      pdisp;      // this pointer displacement
    CV_off16_t      vdisp;      // vbase table displacement
};




//  representation of a 16:16 pointer to far member function for a
//  class with no virtual bases and a single address point


struct CV_PMFR16_FARNVSA {
    CV_uoff16_t     off;        // offset of function (NULL = 0:0)
    unsigned short  seg;        // segment of function
};




//  representation of a 16:16 far pointer to member functions of a
//  class with no virtual bases and multiple address points


struct CV_PMFR16_FARNVMA {
    CV_uoff16_t     off;        // offset of function (NULL = 0:0,x)
    unsigned short  seg;
    signed short    disp;
};




//  representation of a 16:16 far pointer to member function of a
//  class with virtual bases


struct CV_PMFR16_FARVBASE {
    CV_uoff16_t     off;        // offset of function (NULL = 0:0,x,x,x)
    unsigned short  seg;
    CV_off16_t      mdisp;      // displacement to data
    CV_off16_t      pdisp;      // this pointer displacement
    CV_off16_t      vdisp;      // vbase table displacement

};




//  representation of a 32 bit pointer to member function for a
//  class with no virtual bases and a single address point


struct CV_PMFR32_NVSA {
    CV_uoff32_t      off;        // near address of function (NULL = 0L)
};




//  representation of a 32 bit pointer to member function for a
//  class with no virtual bases and multiple address points


struct CV_PMFR32_NVMA {
    CV_uoff32_t     off;        // near address of function (NULL = 0L,x)
    CV_off32_t      disp;
};




//  representation of a 32 bit pointer to member function for a
//  class with virtual bases


struct CV_PMFR32_VBASE {
    CV_uoff32_t     off;        // near address of function (NULL = 0L,x,x,x)
    CV_off32_t      mdisp;      // displacement to data
    CV_off32_t      pdisp;      // this pointer displacement
    CV_off32_t      vdisp;      // vbase table displacement
};





//  Easy leaf - used for generic casting to reference leaf field
//  of a subfield of a complex list

typedef struct lfEasy {
    unsigned short  leaf;           // LF_...
} lfEasy;


/**     The following type records are basically variant records of the
 *      above structure.  The "unsigned short leaf" of the above structure and
 *      the "unsigned short leaf" of the following type definitions are the same
 *      symbol.  When the OMF record is locked via the MHOMFLock API
 *      call, the address of the "unsigned short leaf" is returned
 */

/**     Notes on alignment
 *      Alignment of the fields in most of the type records is done on the
 *      basis of the TYPTYPE record base.  That is why in most of the lf*
 *      records that the CV_typ_t (32-bit types) is located on what appears to
 *      be a offset mod 4 == 2 boundary.  The exception to this rule are those
 *      records that are in a list (lfFieldList, lfMethodList), which are
 *      aligned to their own bases since they don't have the length field
 */

/**** Change log for 16-bit to 32-bit type and symbol records

    Record type         Change (f == field arrangement, p = padding added)
    ----------------------------------------------------------------------
    lfModifer           f
    lfPointer           fp
    lfClass             f
    lfStructure         f
    lfUnion             f
    lfEnum              f
    lfVFTPath           p
    lfPreComp           p
    lfOEM               p
    lfArgList           p
    lfDerived           p
    mlMethod            p   (method list member)
    lfBitField          f
    lfDimCon            f
    lfDimVar            p
    lfIndex             p   (field list member)
    lfBClass            f   (field list member)
    lfVBClass           f   (field list member)
    lfFriendCls         p   (field list member)
    lfFriendFcn         p   (field list member)
    lfMember            f   (field list member)
    lfSTMember          f   (field list member)
    lfVFuncTab          p   (field list member)
    lfVFuncOff          p   (field list member)
    lfNestType          p   (field list member)

    DATASYM32           f
    PROCSYM32           f
    VPATHSYM32          f
    REGREL32            f
    THREADSYM32         f
    PROCSYMMIPS         f


*/

//      Type record for LF_MODIFIER

typedef struct lfModifier_16t {
    unsigned short  leaf;           // LF_MODIFIER_16t
    CV_modifier_t   attr;           // modifier attribute modifier_t
    CV_typ16_t      type;           // modified type
} lfModifier_16t;

typedef struct lfModifier {
    unsigned short  leaf;           // LF_MODIFIER
    CV_typ_t        type;           // modified type
    CV_modifier_t   attr;           // modifier attribute modifier_t
} lfModifier;




//      type record for LF_POINTER

#ifndef __cplusplus
typedef struct lfPointer_16t {
#endif
    struct lfPointerBody_16t {
        unsigned short      leaf;           // LF_POINTER_16t
        struct lfPointerAttr_16t {
            unsigned char   ptrtype     :5; // ordinal specifying pointer type (CV_ptrtype_e)
            unsigned char   ptrmode     :3; // ordinal specifying pointer mode (CV_ptrmode_e)
            unsigned char   isflat32    :1; // true if 0:32 pointer
            unsigned char   isvolatile  :1; // TRUE if volatile pointer
            unsigned char   isconst     :1; // TRUE if const pointer
            unsigned char   isunaligned :1; // TRUE if unaligned pointer
            unsigned char   unused      :4;
        } attr;
        CV_typ16_t  utype;          // type index of the underlying type
#if (defined(__cplusplus) || defined(_MSC_VER)) // for C++ and MS compilers that support unnamed unions
    };
#else
    } u;
#endif
#ifdef  __cplusplus
typedef struct lfPointer_16t : public lfPointerBody_16t {
#endif
    union {
        struct {
            CV_typ16_t      pmclass;    // index of containing class for pointer to member
            unsigned short  pmenum;     // enumeration specifying pm format (CV_pmtype_e)
        } pm;
        unsigned short      bseg;       // base segment if PTR_BASE_SEG
        unsigned char       Sym[1];     // copy of base symbol record (including length)
        struct  {
            CV_typ16_t      index;      // type index if CV_PTR_BASE_TYPE
            unsigned char   name[1];    // name of base type
        } btype;
    } pbase;
} lfPointer_16t;

#ifndef __cplusplus
typedef struct lfPointer {
#endif
    struct lfPointerBody {
        unsigned short      leaf;           // LF_POINTER
        CV_typ_t            utype;          // type index of the underlying type
        struct lfPointerAttr {
            unsigned long   ptrtype     :5; // ordinal specifying pointer type (CV_ptrtype_e)
            unsigned long   ptrmode     :3; // ordinal specifying pointer mode (CV_ptrmode_e)
            unsigned long   isflat32    :1; // true if 0:32 pointer
            unsigned long   isvolatile  :1; // TRUE if volatile pointer
            unsigned long   isconst     :1; // TRUE if const pointer
            unsigned long   isunaligned :1; // TRUE if unaligned pointer
            unsigned long   isrestrict  :1; // TRUE if restricted pointer (allow agressive opts)
            unsigned long   size        :6; // size of pointer (in bytes)
            unsigned long   ismocom     :1; // TRUE if it is a MoCOM pointer (^ or %)
            unsigned long   islref      :1; // TRUE if it is this pointer of member function with & ref-qualifier
            unsigned long   isrref      :1; // TRUE if it is this pointer of member function with && ref-qualifier
            unsigned long   unused      :10;// pad out to 32-bits for following cv_typ_t's
        } attr;
#if (defined(__cplusplus) || defined(_MSC_VER)) // for C++ and MS compilers that support unnamed unions
    };
#else
    } u;
#endif
#ifdef  __cplusplus
typedef struct lfPointer : public lfPointerBody {
#endif
    union {
        struct {
            CV_typ_t        pmclass;    // index of containing class for pointer to member
            unsigned short  pmenum;     // enumeration specifying pm format (CV_pmtype_e)
        } pm;
        unsigned short      bseg;       // base segment if PTR_BASE_SEG
        unsigned char       Sym[1];     // copy of base symbol record (including length)
        struct  {
            CV_typ_t        index;      // type index if CV_PTR_BASE_TYPE
            unsigned char   name[1];    // name of base type
        } btype;
    } pbase;
} lfPointer;




//      type record for LF_ARRAY


typedef struct lfArray_16t {
    unsigned short  leaf;           // LF_ARRAY_16t
    CV_typ16_t      elemtype;       // type index of element type
    CV_typ16_t      idxtype;        // type index of indexing type
    unsigned char   data[CV_ZEROLEN];         // variable length data specifying
                                    // size in bytes and name
} lfArray_16t;

typedef struct lfArray {
    unsigned short  leaf;           // LF_ARRAY
    CV_typ_t        elemtype;       // type index of element type
    CV_typ_t        idxtype;        // type index of indexing type
    unsigned char   data[CV_ZEROLEN];         // variable length data specifying
                                    // size in bytes and name
} lfArray;

typedef struct lfStridedArray {
    unsigned short  leaf;           // LF_STRIDED_ARRAY
    CV_typ_t        elemtype;       // type index of element type
    CV_typ_t        idxtype;        // type index of indexing type
    unsigned long   stride;
    unsigned char   data[CV_ZEROLEN];         // variable length data specifying
                                    // size in bytes and name
} lfStridedArray;




//      type record for LF_VECTOR


typedef struct lfVector {
    unsigned short  leaf;           // LF_VECTOR
    CV_typ_t        elemtype;       // type index of element type
    unsigned long   count;          // number of elements in the vector
    unsigned char   data[CV_ZEROLEN];         // variable length data specifying
                                    // size in bytes and name
} lfVector;




//      type record for LF_MATRIX


typedef struct lfMatrix {
    unsigned short  leaf;           // LF_MATRIX
    CV_typ_t        elemtype;       // type index of element type
    unsigned long   rows;           // number of rows
    unsigned long   cols;           // number of columns
    unsigned long   majorStride;
    CV_matrixattr_t matattr;        // attributes
    unsigned char   data[CV_ZEROLEN];         // variable length data specifying
                                    // size in bytes and name
} lfMatrix;




//      type record for LF_CLASS, LF_STRUCTURE


typedef struct lfClass_16t {
    unsigned short  leaf;           // LF_CLASS_16t, LF_STRUCT_16t
    unsigned short  count;          // count of number of elements in class
    CV_typ16_t      field;          // type index of LF_FIELD descriptor list
    CV_prop_t       property;       // property attribute field (prop_t)
    CV_typ16_t      derived;        // type index of derived from list if not zero
    CV_typ16_t      vshape;         // type index of vshape table for this class
    unsigned char   data[CV_ZEROLEN];         // data describing length of structure in
                                    // bytes and name
} lfClass_16t;
typedef lfClass_16t lfStructure_16t;


typedef struct lfClass {
    unsigned short  leaf;           // LF_CLASS, LF_STRUCT, LF_INTERFACE
    unsigned short  count;          // count of number of elements in class
    CV_prop_t       property;       // property attribute field (prop_t)
    CV_typ_t        field;          // type index of LF_FIELD descriptor list
    CV_typ_t        derived;        // type index of derived from list if not zero
    CV_typ_t        vshape;         // type index of vshape table for this class
    unsigned char   data[CV_ZEROLEN];         // data describing length of structure in
                                    // bytes and name
} lfClass;
typedef lfClass lfStructure;
typedef lfClass lfInterface;

//      type record for LF_UNION


typedef struct lfUnion_16t {
    unsigned short  leaf;           // LF_UNION_16t
    unsigned short  count;          // count of number of elements in class
    CV_typ16_t      field;          // type index of LF_FIELD descriptor list
    CV_prop_t       property;       // property attribute field
    unsigned char   data[CV_ZEROLEN];         // variable length data describing length of
                                    // structure and name
} lfUnion_16t;


typedef struct lfUnion {
    unsigned short  leaf;           // LF_UNION
    unsigned short  count;          // count of number of elements in class
    CV_prop_t       property;       // property attribute field
    CV_typ_t        field;          // type index of LF_FIELD descriptor list
    unsigned char   data[CV_ZEROLEN];         // variable length data describing length of
                                    // structure and name
} lfUnion;


//      type record for LF_ALIAS

typedef struct lfAlias {
    unsigned short  leaf;           // LF_ALIAS
    CV_typ_t        utype;          // underlying type
    unsigned char   Name[1];        // alias name
} lfAlias;

// Item Id is a stricter typeindex which may referenced from symbol stream.
// The code item always had a name.

typedef CV_typ_t CV_ItemId;

typedef struct lfFuncId {
    unsigned short  leaf;       // LF_FUNC_ID
    CV_ItemId       scopeId;    // parent scope of the ID, 0 if global
    CV_typ_t        type;       // function type
    unsigned char   name[CV_ZEROLEN]; 
} lfFuncId;

typedef struct lfMFuncId {
    unsigned short  leaf;       // LF_MFUNC_ID
    CV_typ_t        parentType; // type index of parent
    CV_typ_t        type;       // function type
    unsigned char   name[CV_ZEROLEN]; 
} lfMFuncId;

typedef struct lfStringId {
    unsigned short  leaf;       // LF_STRING_ID
    CV_ItemId       id;         // ID to list of sub string IDs
    unsigned char   name[CV_ZEROLEN];
} lfStringId;

typedef struct lfUdtSrcLine {
    unsigned short leaf;        // LF_UDT_SRC_LINE
    CV_typ_t       type;        // UDT's type index
    CV_ItemId      src;         // index to LF_STRING_ID record where source file name is saved
    unsigned long  line;        // line number
} lfUdtSrcLine;

typedef struct lfUdtModSrcLine {
    unsigned short leaf;        // LF_UDT_MOD_SRC_LINE
    CV_typ_t       type;        // UDT's type index
    CV_ItemId      src;         // index into string table where source file name is saved
    unsigned long  line;        // line number
    unsigned short imod;        // module that contributes this UDT definition 
} lfUdtModSrcLine;

typedef enum CV_BuildInfo_e {
    CV_BuildInfo_CurrentDirectory = 0,
    CV_BuildInfo_BuildTool        = 1,    // Cl.exe
    CV_BuildInfo_SourceFile       = 2,    // foo.cpp
    CV_BuildInfo_ProgramDatabaseFile = 3, // foo.pdb
    CV_BuildInfo_CommandArguments = 4,    // -I etc
    CV_BUILDINFO_KNOWN
} CV_BuildInfo_e;

// type record for build information

typedef struct lfBuildInfo {
    unsigned short  leaf;                    // LF_BUILDINFO
    unsigned short  count;                   // number of arguments
    CV_ItemId       arg[CV_BUILDINFO_KNOWN]; // arguments as CodeItemId
} lfBuildInfo;

//      type record for LF_MANAGED

typedef struct lfManaged {
    unsigned short  leaf;           // LF_MANAGED
    unsigned char   Name[1];        // utf8, zero terminated managed type name
} lfManaged;


//      type record for LF_ENUM


typedef struct lfEnum_16t {
    unsigned short  leaf;           // LF_ENUM_16t
    unsigned short  count;          // count of number of elements in class
    CV_typ16_t      utype;          // underlying type of the enum
    CV_typ16_t      field;          // type index of LF_FIELD descriptor list
    CV_prop_t       property;       // property attribute field
    unsigned char   Name[1];        // length prefixed name of enum
} lfEnum_16t;

typedef struct lfEnum {
    unsigned short  leaf;           // LF_ENUM
    unsigned short  count;          // count of number of elements in class
    CV_prop_t       property;       // property attribute field
    CV_typ_t        utype;          // underlying type of the enum
    CV_typ_t        field;          // type index of LF_FIELD descriptor list
    unsigned char   Name[1];        // length prefixed name of enum
} lfEnum;



//      Type record for LF_PROCEDURE


typedef struct lfProc_16t {
    unsigned short  leaf;           // LF_PROCEDURE_16t
    CV_typ16_t      rvtype;         // type index of return value
    unsigned char   calltype;       // calling convention (CV_call_t)
    CV_funcattr_t   funcattr;       // attributes
    unsigned short  parmcount;      // number of parameters
    CV_typ16_t      arglist;        // type index of argument list
} lfProc_16t;

typedef struct lfProc {
    unsigned short  leaf;           // LF_PROCEDURE
    CV_typ_t        rvtype;         // type index of return value
    unsigned char   calltype;       // calling convention (CV_call_t)
    CV_funcattr_t   funcattr;       // attributes
    unsigned short  parmcount;      // number of parameters
    CV_typ_t        arglist;        // type index of argument list
} lfProc;



//      Type record for member function


typedef struct lfMFunc_16t {
    unsigned short  leaf;           // LF_MFUNCTION_16t
    CV_typ16_t      rvtype;         // type index of return value
    CV_typ16_t      classtype;      // type index of containing class
    CV_typ16_t      thistype;       // type index of this pointer (model specific)
    unsigned char   calltype;       // calling convention (call_t)
    CV_funcattr_t   funcattr;       // attributes
    unsigned short  parmcount;      // number of parameters
    CV_typ16_t      arglist;        // type index of argument list
    long            thisadjust;     // this adjuster (long because pad required anyway)
} lfMFunc_16t;

typedef struct lfMFunc {
    unsigned short  leaf;           // LF_MFUNCTION
    CV_typ_t        rvtype;         // type index of return value
    CV_typ_t        classtype;      // type index of containing class
    CV_typ_t        thistype;       // type index of this pointer (model specific)
    unsigned char   calltype;       // calling convention (call_t)
    CV_funcattr_t   funcattr;       // attributes
    unsigned short  parmcount;      // number of parameters
    CV_typ_t        arglist;        // type index of argument list
    long            thisadjust;     // this adjuster (long because pad required anyway)
} lfMFunc;




//     type record for virtual function table shape


typedef struct lfVTShape {
    unsigned short  leaf;       // LF_VTSHAPE
    unsigned short  count;      // number of entries in vfunctable
    unsigned char   desc[CV_ZEROLEN];     // 4 bit (CV_VTS_desc) descriptors
} lfVTShape;

//     type record for a virtual function table
typedef struct lfVftable {
    unsigned short  leaf;             // LF_VFTABLE
    CV_typ_t        type;             // class/structure that owns the vftable
    CV_typ_t        baseVftable;      // vftable from which this vftable is derived
    unsigned long   offsetInObjectLayout; // offset of the vfptr to this table, relative to the start of the object layout.
    unsigned long   len;              // length of the Names array below in bytes.
    unsigned char   Names[1];         // array of names.
                                      // The first is the name of the vtable.
                                      // The others are the names of the methods.
                                      // TS-TODO: replace a name with a NamedCodeItem once Weiping is done, to
                                      //    avoid duplication of method names.
} lfVftable;

//      type record for cobol0


typedef struct lfCobol0_16t {
    unsigned short  leaf;       // LF_COBOL0_16t
    CV_typ16_t      type;       // parent type record index
    unsigned char   data[CV_ZEROLEN];
} lfCobol0_16t;

typedef struct lfCobol0 {
    unsigned short  leaf;       // LF_COBOL0
    CV_typ_t        type;       // parent type record index
    unsigned char   data[CV_ZEROLEN];
} lfCobol0;




//      type record for cobol1


typedef struct lfCobol1 {
    unsigned short  leaf;       // LF_COBOL1
    unsigned char   data[CV_ZEROLEN];
} lfCobol1;




//      type record for basic array


typedef struct lfBArray_16t {
    unsigned short  leaf;       // LF_BARRAY_16t
    CV_typ16_t      utype;      // type index of underlying type
} lfBArray_16t;

typedef struct lfBArray {
    unsigned short  leaf;       // LF_BARRAY
    CV_typ_t        utype;      // type index of underlying type
} lfBArray;

//      type record for assembler labels


typedef struct lfLabel {
    unsigned short  leaf;       // LF_LABEL
    unsigned short  mode;       // addressing mode of label
} lfLabel;



//      type record for dimensioned arrays


typedef struct lfDimArray_16t {
    unsigned short  leaf;       // LF_DIMARRAY_16t
    CV_typ16_t      utype;      // underlying type of the array
    CV_typ16_t      diminfo;    // dimension information
    unsigned char   name[1];    // length prefixed name
} lfDimArray_16t;

typedef struct lfDimArray {
    unsigned short  leaf;       // LF_DIMARRAY
    CV_typ_t        utype;      // underlying type of the array
    CV_typ_t        diminfo;    // dimension information
    unsigned char   name[1];    // length prefixed name
} lfDimArray;



//      type record describing path to virtual function table


typedef struct lfVFTPath_16t {
    unsigned short  leaf;       // LF_VFTPATH_16t
    unsigned short  count;      // count of number of bases in path
    CV_typ16_t      base[1];    // bases from root to leaf
} lfVFTPath_16t;

typedef struct lfVFTPath {
    unsigned short  leaf;       // LF_VFTPATH
    unsigned long   count;      // count of number of bases in path
    CV_typ_t        base[1];    // bases from root to leaf
} lfVFTPath;


//      type record describing inclusion of precompiled types


typedef struct lfPreComp_16t {
    unsigned short  leaf;       // LF_PRECOMP_16t
    unsigned short  start;      // starting type index included
    unsigned short  count;      // number of types in inclusion
    unsigned long   signature;  // signature
    unsigned char   name[CV_ZEROLEN];     // length prefixed name of included type file
} lfPreComp_16t;

typedef struct lfPreComp {
    unsigned short  leaf;       // LF_PRECOMP
    unsigned long   start;      // starting type index included
    unsigned long   count;      // number of types in inclusion
    unsigned long   signature;  // signature
    unsigned char   name[CV_ZEROLEN];     // length prefixed name of included type file
} lfPreComp;



//      type record describing end of precompiled types that can be
//      included by another file


typedef struct lfEndPreComp {
    unsigned short  leaf;       // LF_ENDPRECOMP
    unsigned long   signature;  // signature
} lfEndPreComp;





//      type record for OEM definable type strings


typedef struct lfOEM_16t {
    unsigned short  leaf;       // LF_OEM_16t
    unsigned short  cvOEM;      // MS assigned OEM identified
    unsigned short  recOEM;     // OEM assigned type identifier
    unsigned short  count;      // count of type indices to follow
    CV_typ16_t      index[CV_ZEROLEN];  // array of type indices followed
                                // by OEM defined data
} lfOEM_16t;

typedef struct lfOEM {
    unsigned short  leaf;       // LF_OEM
    unsigned short  cvOEM;      // MS assigned OEM identified
    unsigned short  recOEM;     // OEM assigned type identifier
    unsigned long   count;      // count of type indices to follow
    CV_typ_t        index[CV_ZEROLEN];  // array of type indices followed
                                // by OEM defined data
} lfOEM;

#define OEM_MS_FORTRAN90        0xF090
#define OEM_ODI                 0x0010
#define OEM_THOMSON_SOFTWARE    0x5453
#define OEM_ODI_REC_BASELIST    0x0000

typedef struct lfOEM2 {
    unsigned short  leaf;       // LF_OEM2
    unsigned char   idOem[16];  // an oem ID (GUID)
    unsigned long   count;      // count of type indices to follow
    CV_typ_t        index[CV_ZEROLEN];  // array of type indices followed
                                // by OEM defined data
} lfOEM2;

//      type record describing using of a type server

typedef struct lfTypeServer {
    unsigned short  leaf;       // LF_TYPESERVER
    unsigned long   signature;  // signature
    unsigned long   age;        // age of database used by this module
    unsigned char   name[CV_ZEROLEN];     // length prefixed name of PDB
} lfTypeServer;

//      type record describing using of a type server with v7 (GUID) signatures

typedef struct lfTypeServer2 {
    unsigned short  leaf;       // LF_TYPESERVER2
    SIG70           sig70;      // guid signature
    unsigned long   age;        // age of database used by this module
    unsigned char   name[CV_ZEROLEN];     // length prefixed name of PDB
} lfTypeServer2;

//      description of type records that can be referenced from
//      type records referenced by symbols



//      type record for skip record


typedef struct lfSkip_16t {
    unsigned short  leaf;       // LF_SKIP_16t
    CV_typ16_t      type;       // next valid index
    unsigned char   data[CV_ZEROLEN];     // pad data
} lfSkip_16t;

typedef struct lfSkip {
    unsigned short  leaf;       // LF_SKIP
    CV_typ_t        type;       // next valid index
    unsigned char   data[CV_ZEROLEN];     // pad data
} lfSkip;



//      argument list leaf


typedef struct lfArgList_16t {
    unsigned short  leaf;           // LF_ARGLIST_16t
    unsigned short  count;          // number of arguments
    CV_typ16_t      arg[CV_ZEROLEN];      // number of arguments
} lfArgList_16t;

typedef struct lfArgList {
    unsigned short  leaf;           // LF_ARGLIST, LF_SUBSTR_LIST
    unsigned long   count;          // number of arguments
    CV_typ_t        arg[CV_ZEROLEN];      // number of arguments
} lfArgList;




//      derived class list leaf


typedef struct lfDerived_16t {
    unsigned short  leaf;           // LF_DERIVED_16t
    unsigned short  count;          // number of arguments
    CV_typ16_t      drvdcls[CV_ZEROLEN];      // type indices of derived classes
} lfDerived_16t;

typedef struct lfDerived {
    unsigned short  leaf;           // LF_DERIVED
    unsigned long   count;          // number of arguments
    CV_typ_t        drvdcls[CV_ZEROLEN];      // type indices of derived classes
} lfDerived;




//      leaf for default arguments


typedef struct lfDefArg_16t {
    unsigned short  leaf;               // LF_DEFARG_16t
    CV_typ16_t      type;               // type of resulting expression
    unsigned char   expr[CV_ZEROLEN];   // length prefixed expression string
} lfDefArg_16t;

typedef struct lfDefArg {
    unsigned short  leaf;               // LF_DEFARG
    CV_typ_t        type;               // type of resulting expression
    unsigned char   expr[CV_ZEROLEN];   // length prefixed expression string
} lfDefArg;



//      list leaf
//          This list should no longer be used because the utilities cannot
//          verify the contents of the list without knowing what type of list
//          it is.  New specific leaf indices should be used instead.


typedef struct lfList {
    unsigned short  leaf;           // LF_LIST
    char            data[CV_ZEROLEN];         // data format specified by indexing type
} lfList;




//      field list leaf
//      This is the header leaf for a complex list of class and structure
//      subfields.


typedef struct lfFieldList_16t {
    unsigned short  leaf;           // LF_FIELDLIST_16t
    char            data[CV_ZEROLEN];         // field list sub lists
} lfFieldList_16t;


typedef struct lfFieldList {
    unsigned short  leaf;           // LF_FIELDLIST
    char            data[CV_ZEROLEN];         // field list sub lists
} lfFieldList;







//  type record for non-static methods and friends in overloaded method list

typedef struct mlMethod_16t {
    CV_fldattr_t   attr;           // method attribute
    CV_typ16_t     index;          // index to type record for procedure
    unsigned long  vbaseoff[CV_ZEROLEN];    // offset in vfunctable if intro virtual
} mlMethod_16t;

typedef struct mlMethod {
    CV_fldattr_t    attr;           // method attribute
    _2BYTEPAD       pad0;           // internal padding, must be 0
    CV_typ_t        index;          // index to type record for procedure
    unsigned long   vbaseoff[CV_ZEROLEN];    // offset in vfunctable if intro virtual
} mlMethod;


typedef struct lfMethodList_16t {
    unsigned short leaf;
    unsigned char  mList[CV_ZEROLEN];         // really a mlMethod_16t type
} lfMethodList_16t;

typedef struct lfMethodList {
    unsigned short leaf;
    unsigned char  mList[CV_ZEROLEN];         // really a mlMethod type
} lfMethodList;





//      type record for LF_BITFIELD


typedef struct lfBitfield_16t {
    unsigned short  leaf;           // LF_BITFIELD_16t
    unsigned char   length;
    unsigned char   position;
    CV_typ16_t      type;           // type of bitfield

} lfBitfield_16t;

typedef struct lfBitfield {
    unsigned short  leaf;           // LF_BITFIELD
    CV_typ_t        type;           // type of bitfield
    unsigned char   length;
    unsigned char   position;

} lfBitfield;




//      type record for dimensioned array with constant bounds


typedef struct lfDimCon_16t {
    unsigned short  leaf;           // LF_DIMCONU_16t or LF_DIMCONLU_16t
    unsigned short  rank;           // number of dimensions
    CV_typ16_t      typ;            // type of index
    unsigned char   dim[CV_ZEROLEN];          // array of dimension information with
                                    // either upper bounds or lower/upper bound
} lfDimCon_16t;

typedef struct lfDimCon {
    unsigned short  leaf;           // LF_DIMCONU or LF_DIMCONLU
    CV_typ_t        typ;            // type of index
    unsigned short  rank;           // number of dimensions
    unsigned char   dim[CV_ZEROLEN];          // array of dimension information with
                                    // either upper bounds or lower/upper bound
} lfDimCon;




//      type record for dimensioned array with variable bounds


typedef struct lfDimVar_16t {
    unsigned short  leaf;           // LF_DIMVARU_16t or LF_DIMVARLU_16t
    unsigned short  rank;           // number of dimensions
    CV_typ16_t      typ;            // type of index
    CV_typ16_t      dim[CV_ZEROLEN];          // array of type indices for either
                                    // variable upper bound or variable
                                    // lower/upper bound.  The referenced
                                    // types must be LF_REFSYM or T_VOID
} lfDimVar_16t;

typedef struct lfDimVar {
    unsigned short  leaf;           // LF_DIMVARU or LF_DIMVARLU
    unsigned long   rank;           // number of dimensions
    CV_typ_t        typ;            // type of index
    CV_typ_t        dim[CV_ZEROLEN];          // array of type indices for either
                                    // variable upper bound or variable
                                    // lower/upper bound.  The count of type
                                    // indices is rank or rank*2 depending on
                                    // whether it is LFDIMVARU or LF_DIMVARLU.
                                    // The referenced types must be
                                    // LF_REFSYM or T_VOID
} lfDimVar;




//      type record for referenced symbol


typedef struct lfRefSym {
    unsigned short  leaf;           // LF_REFSYM
    unsigned char   Sym[1];         // copy of referenced symbol record
                                    // (including length)
} lfRefSym;



//      type record for generic HLSL type


typedef struct lfHLSL {
    unsigned short  leaf;                 // LF_HLSL
    CV_typ_t        subtype;              // sub-type index, if any
    unsigned short  kind;                 // kind of built-in type from CV_builtin_e
    unsigned short  numprops :  4;        // number of numeric properties
    unsigned short  unused   : 12;        // padding, must be 0
    unsigned char   data[CV_ZEROLEN];     // variable-length array of numeric properties
                                          // followed by byte size
} lfHLSL;




//      type record for a generalized built-in type modifier


typedef struct lfModifierEx {
    unsigned short  leaf;                 // LF_MODIFIER_EX
    CV_typ_t        type;                 // type being modified
    unsigned short  count;                // count of modifier values
    unsigned short  mods[CV_ZEROLEN];     // modifiers from CV_modifier_e
} lfModifierEx;




/**     the following are numeric leaves.  They are used to indicate the
 *      size of the following variable length data.  When the numeric
 *      data is a single byte less than 0x8000, then the data is output
 *      directly.  If the data is more the 0x8000 or is a negative value,
 *      then the data is preceeded by the proper index.
 */



//      signed character leaf

typedef struct lfChar {
    unsigned short  leaf;           // LF_CHAR
    signed char     val;            // signed 8-bit value
} lfChar;




//      signed short leaf

typedef struct lfShort {
    unsigned short  leaf;           // LF_SHORT
    short           val;            // signed 16-bit value
} lfShort;




//      unsigned short leaf

typedef struct lfUShort {
    unsigned short  leaf;           // LF_unsigned short
    unsigned short  val;            // unsigned 16-bit value
} lfUShort;




//      signed long leaf

typedef struct lfLong {
    unsigned short  leaf;           // LF_LONG
    long            val;            // signed 32-bit value
} lfLong;




//      unsigned long leaf

typedef struct lfULong {
    unsigned short  leaf;           // LF_ULONG
    unsigned long   val;            // unsigned 32-bit value
} lfULong;




//      signed quad leaf

typedef struct lfQuad {
    unsigned short  leaf;           // LF_QUAD
    unsigned char   val[8];         // signed 64-bit value
} lfQuad;




//      unsigned quad leaf

typedef struct lfUQuad {
    unsigned short  leaf;           // LF_UQUAD
    unsigned char   val[8];         // unsigned 64-bit value
} lfUQuad;


//      signed int128 leaf

typedef struct lfOct {
    unsigned short  leaf;           // LF_OCT
    unsigned char   val[16];        // signed 128-bit value
} lfOct;

//      unsigned int128 leaf

typedef struct lfUOct {
    unsigned short  leaf;           // LF_UOCT
    unsigned char   val[16];        // unsigned 128-bit value
} lfUOct;




//      real 16-bit leaf

typedef struct lfReal16 {
    unsigned short  leaf;           // LF_REAL16
    unsigned short  val;            // 16-bit real value
} lfReal16;




//      real 32-bit leaf

typedef struct lfReal32 {
    unsigned short  leaf;           // LF_REAL32
    float           val;            // 32-bit real value
} lfReal32;




//      real 48-bit leaf

typedef struct lfReal48 {
    unsigned short  leaf;           // LF_REAL48
    unsigned char   val[6];         // 48-bit real value
} lfReal48;




//      real 64-bit leaf

typedef struct lfReal64 {
    unsigned short  leaf;           // LF_REAL64
    double          val;            // 64-bit real value
} lfReal64;




//      real 80-bit leaf

typedef struct lfReal80 {
    unsigned short  leaf;           // LF_REAL80
    FLOAT10         val;            // real 80-bit value
} lfReal80;




//      real 128-bit leaf

typedef struct lfReal128 {
    unsigned short  leaf;           // LF_REAL128
    char            val[16];        // real 128-bit value
} lfReal128;




//      complex 32-bit leaf

typedef struct lfCmplx32 {
    unsigned short  leaf;           // LF_COMPLEX32
    float           val_real;       // real component
    float           val_imag;       // imaginary component
} lfCmplx32;




//      complex 64-bit leaf

typedef struct lfCmplx64 {
    unsigned short  leaf;           // LF_COMPLEX64
    double          val_real;       // real component
    double          val_imag;       // imaginary component
} flCmplx64;




//      complex 80-bit leaf

typedef struct lfCmplx80 {
    unsigned short  leaf;           // LF_COMPLEX80
    FLOAT10         val_real;       // real component
    FLOAT10         val_imag;       // imaginary component
} lfCmplx80;




//      complex 128-bit leaf

typedef struct lfCmplx128 {
    unsigned short  leaf;           // LF_COMPLEX128
    char            val_real[16];   // real component
    char            val_imag[16];   // imaginary component
} lfCmplx128;



//  variable length numeric field

typedef struct lfVarString {
    unsigned short  leaf;       // LF_VARSTRING
    unsigned short  len;        // length of value in bytes
    unsigned char   value[CV_ZEROLEN];  // value
} lfVarString;

//***********************************************************************


//      index leaf - contains type index of another leaf
//      a major use of this leaf is to allow the compilers to emit a
//      long complex list (LF_FIELD) in smaller pieces.

typedef struct lfIndex_16t {
    unsigned short  leaf;           // LF_INDEX_16t
    CV_typ16_t      index;          // type index of referenced leaf
} lfIndex_16t;

typedef struct lfIndex {
    unsigned short  leaf;           // LF_INDEX
    _2BYTEPAD       pad0;           // internal padding, must be 0
    CV_typ_t        index;          // type index of referenced leaf
} lfIndex;


//      subfield record for base class field

typedef struct lfBClass_16t {
    unsigned short  leaf;           // LF_BCLASS_16t
    CV_typ16_t      index;          // type index of base class
    CV_fldattr_t    attr;           // attribute
    unsigned char   offset[CV_ZEROLEN];       // variable length offset of base within class
} lfBClass_16t;

typedef struct lfBClass {
    unsigned short  leaf;           // LF_BCLASS, LF_BINTERFACE
    CV_fldattr_t    attr;           // attribute
    CV_typ_t        index;          // type index of base class
    unsigned char   offset[CV_ZEROLEN];       // variable length offset of base within class
} lfBClass;
typedef lfBClass lfBInterface;




//      subfield record for direct and indirect virtual base class field

typedef struct lfVBClass_16t {
    unsigned short  leaf;           // LF_VBCLASS_16t | LV_IVBCLASS_16t
    CV_typ16_t      index;          // type index of direct virtual base class
    CV_typ16_t      vbptr;          // type index of virtual base pointer
    CV_fldattr_t    attr;           // attribute
    unsigned char   vbpoff[CV_ZEROLEN];       // virtual base pointer offset from address point
                                    // followed by virtual base offset from vbtable
} lfVBClass_16t;

typedef struct lfVBClass {
    unsigned short  leaf;           // LF_VBCLASS | LV_IVBCLASS
    CV_fldattr_t    attr;           // attribute
    CV_typ_t        index;          // type index of direct virtual base class
    CV_typ_t        vbptr;          // type index of virtual base pointer
    unsigned char   vbpoff[CV_ZEROLEN];       // virtual base pointer offset from address point
                                    // followed by virtual base offset from vbtable
} lfVBClass;





//      subfield record for friend class


typedef struct lfFriendCls_16t {
    unsigned short  leaf;           // LF_FRIENDCLS_16t
    CV_typ16_t      index;          // index to type record of friend class
} lfFriendCls_16t;

typedef struct lfFriendCls {
    unsigned short  leaf;           // LF_FRIENDCLS
    _2BYTEPAD       pad0;           // internal padding, must be 0
    CV_typ_t        index;          // index to type record of friend class
} lfFriendCls;





//      subfield record for friend function


typedef struct lfFriendFcn_16t {
    unsigned short  leaf;           // LF_FRIENDFCN_16t
    CV_typ16_t      index;          // index to type record of friend function
    unsigned char   Name[1];        // name of friend function
} lfFriendFcn_16t;

typedef struct lfFriendFcn {
    unsigned short  leaf;           // LF_FRIENDFCN
    _2BYTEPAD       pad0;           // internal padding, must be 0
    CV_typ_t        index;          // index to type record of friend function
    unsigned char   Name[1];        // name of friend function
} lfFriendFcn;



//      subfield record for non-static data members

typedef struct lfMember_16t {
    unsigned short  leaf;           // LF_MEMBER_16t
    CV_typ16_t      index;          // index of type record for field
    CV_fldattr_t    attr;           // attribute mask
    unsigned char   offset[CV_ZEROLEN];       // variable length offset of field followed
                                    // by length prefixed name of field
} lfMember_16t;

typedef struct lfMember {
    unsigned short  leaf;           // LF_MEMBER
    CV_fldattr_t    attr;           // attribute mask
    CV_typ_t        index;          // index of type record for field
    unsigned char   offset[CV_ZEROLEN];       // variable length offset of field followed
                                    // by length prefixed name of field
} lfMember;



//  type record for static data members

typedef struct lfSTMember_16t {
    unsigned short  leaf;           // LF_STMEMBER_16t
    CV_typ16_t      index;          // index of type record for field
    CV_fldattr_t    attr;           // attribute mask
    unsigned char   Name[1];        // length prefixed name of field
} lfSTMember_16t;

typedef struct lfSTMember {
    unsigned short  leaf;           // LF_STMEMBER
    CV_fldattr_t    attr;           // attribute mask
    CV_typ_t        index;          // index of type record for field
    unsigned char   Name[1];        // length prefixed name of field
} lfSTMember;



//      subfield record for virtual function table pointer

typedef struct lfVFuncTab_16t {
    unsigned short  leaf;           // LF_VFUNCTAB_16t
    CV_typ16_t      type;           // type index of pointer
} lfVFuncTab_16t;

typedef struct lfVFuncTab {
    unsigned short  leaf;           // LF_VFUNCTAB
    _2BYTEPAD       pad0;           // internal padding, must be 0
    CV_typ_t        type;           // type index of pointer
} lfVFuncTab;



//      subfield record for virtual function table pointer with offset

typedef struct lfVFuncOff_16t {
    unsigned short  leaf;           // LF_VFUNCOFF_16t
    CV_typ16_t      type;           // type index of pointer
    CV_off32_t      offset;         // offset of virtual function table pointer
} lfVFuncOff_16t;

typedef struct lfVFuncOff {
    unsigned short  leaf;           // LF_VFUNCOFF
    _2BYTEPAD       pad0;           // internal padding, must be 0.
    CV_typ_t        type;           // type index of pointer
    CV_off32_t      offset;         // offset of virtual function table pointer
} lfVFuncOff;



//      subfield record for overloaded method list


typedef struct lfMethod_16t {
    unsigned short  leaf;           // LF_METHOD_16t
    unsigned short  count;          // number of occurrences of function
    CV_typ16_t      mList;          // index to LF_METHODLIST record
    unsigned char   Name[1];        // length prefixed name of method
} lfMethod_16t;

typedef struct lfMethod {
    unsigned short  leaf;           // LF_METHOD
    unsigned short  count;          // number of occurrences of function
    CV_typ_t        mList;          // index to LF_METHODLIST record
    unsigned char   Name[1];        // length prefixed name of method
} lfMethod;



//      subfield record for nonoverloaded method


typedef struct lfOneMethod_16t {
    unsigned short leaf;            // LF_ONEMETHOD_16t
    CV_fldattr_t   attr;            // method attribute
    CV_typ16_t     index;           // index to type record for procedure
    unsigned long  vbaseoff[CV_ZEROLEN];    // offset in vfunctable if
                                    // intro virtual followed by
                                    // length prefixed name of method
} lfOneMethod_16t;

typedef struct lfOneMethod {
    unsigned short leaf;            // LF_ONEMETHOD
    CV_fldattr_t   attr;            // method attribute
    CV_typ_t       index;           // index to type record for procedure
    unsigned long  vbaseoff[CV_ZEROLEN];    // offset in vfunctable if
                                    // intro virtual followed by
                                    // length prefixed name of method
} lfOneMethod;


//      subfield record for enumerate

typedef struct lfEnumerate {
    unsigned short  leaf;       // LF_ENUMERATE
    CV_fldattr_t    attr;       // access
    unsigned char   value[CV_ZEROLEN];    // variable length value field followed
                                // by length prefixed name
} lfEnumerate;


//  type record for nested (scoped) type definition

typedef struct lfNestType_16t {
    unsigned short  leaf;       // LF_NESTTYPE_16t
    CV_typ16_t      index;      // index of nested type definition
    unsigned char   Name[1];    // length prefixed type name
} lfNestType_16t;

typedef struct lfNestType {
    unsigned short  leaf;       // LF_NESTTYPE
    _2BYTEPAD       pad0;       // internal padding, must be 0
    CV_typ_t        index;      // index of nested type definition
    unsigned char   Name[1];    // length prefixed type name
} lfNestType;

//  type record for nested (scoped) type definition, with attributes
//  new records for vC v5.0, no need to have 16-bit ti versions.

typedef struct lfNestTypeEx {
    unsigned short  leaf;       // LF_NESTTYPEEX
    CV_fldattr_t    attr;       // member access
    CV_typ_t        index;      // index of nested type definition
    unsigned char   Name[1];    // length prefixed type name
} lfNestTypeEx;

//  type record for modifications to members

typedef struct lfMemberModify {
    unsigned short  leaf;       // LF_MEMBERMODIFY
    CV_fldattr_t    attr;       // the new attributes
    CV_typ_t        index;      // index of base class type definition
    unsigned char   Name[1];    // length prefixed member name
} lfMemberModify;

//  type record for pad leaf

typedef struct lfPad {
    unsigned char   leaf;
} SYM_PAD;



//  Symbol definitions

typedef enum SYM_ENUM_e {
    S_COMPILE       =  0x0001,  // Compile flags symbol
    S_REGISTER_16t  =  0x0002,  // Register variable
    S_CONSTANT_16t  =  0x0003,  // constant symbol
    S_UDT_16t       =  0x0004,  // User defined type
    S_SSEARCH       =  0x0005,  // Start Search
    S_END           =  0x0006,  // Block, procedure, "with" or thunk end
    S_SKIP          =  0x0007,  // Reserve symbol space in $$Symbols table
    S_CVRESERVE     =  0x0008,  // Reserved symbol for CV internal use
    S_OBJNAME_ST    =  0x0009,  // path to object file name
    S_ENDARG        =  0x000a,  // end of argument/return list
    S_COBOLUDT_16t  =  0x000b,  // special UDT for cobol that does not symbol pack
    S_MANYREG_16t   =  0x000c,  // multiple register variable
    S_RETURN        =  0x000d,  // return description symbol
    S_ENTRYTHIS     =  0x000e,  // description of this pointer on entry

    S_BPREL16       =  0x0100,  // BP-relative
    S_LDATA16       =  0x0101,  // Module-local symbol
    S_GDATA16       =  0x0102,  // Global data symbol
    S_PUB16         =  0x0103,  // a public symbol
    S_LPROC16       =  0x0104,  // Local procedure start
    S_GPROC16       =  0x0105,  // Global procedure start
    S_THUNK16       =  0x0106,  // Thunk Start
    S_BLOCK16       =  0x0107,  // block start
    S_WITH16        =  0x0108,  // with start
    S_LABEL16       =  0x0109,  // code label
    S_CEXMODEL16    =  0x010a,  // change execution model
    S_VFTABLE16     =  0x010b,  // address of virtual function table
    S_REGREL16      =  0x010c,  // register relative address

    S_BPREL32_16t   =  0x0200,  // BP-relative
    S_LDATA32_16t   =  0x0201,  // Module-local symbol
    S_GDATA32_16t   =  0x0202,  // Global data symbol
    S_PUB32_16t     =  0x0203,  // a public symbol (CV internal reserved)
    S_LPROC32_16t   =  0x0204,  // Local procedure start
    S_GPROC32_16t   =  0x0205,  // Global procedure start
    S_THUNK32_ST    =  0x0206,  // Thunk Start
    S_BLOCK32_ST    =  0x0207,  // block start
    S_WITH32_ST     =  0x0208,  // with start
    S_LABEL32_ST    =  0x0209,  // code label
    S_CEXMODEL32    =  0x020a,  // change execution model
    S_VFTABLE32_16t =  0x020b,  // address of virtual function table
    S_REGREL32_16t  =  0x020c,  // register relative address
    S_LTHREAD32_16t =  0x020d,  // local thread storage
    S_GTHREAD32_16t =  0x020e,  // global thread storage
    S_SLINK32       =  0x020f,  // static link for MIPS EH implementation

    S_LPROCMIPS_16t =  0x0300,  // Local procedure start
    S_GPROCMIPS_16t =  0x0301,  // Global procedure start

    // if these ref symbols have names following then the names are in ST format
    S_PROCREF_ST    =  0x0400,  // Reference to a procedure
    S_DATAREF_ST    =  0x0401,  // Reference to data
    S_ALIGN         =  0x0402,  // Used for page alignment of symbols

    S_LPROCREF_ST   =  0x0403,  // Local Reference to a procedure
    S_OEM           =  0x0404,  // OEM defined symbol

    // sym records with 32-bit types embedded instead of 16-bit
    // all have 0x1000 bit set for easy identification
    // only do the 32-bit target versions since we don't really
    // care about 16-bit ones anymore.
    S_TI16_MAX          =  0x1000,

    S_REGISTER_ST   =  0x1001,  // Register variable
    S_CONSTANT_ST   =  0x1002,  // constant symbol
    S_UDT_ST        =  0x1003,  // User defined type
    S_COBOLUDT_ST   =  0x1004,  // special UDT for cobol that does not symbol pack
    S_MANYREG_ST    =  0x1005,  // multiple register variable
    S_BPREL32_ST    =  0x1006,  // BP-relative
    S_LDATA32_ST    =  0x1007,  // Module-local symbol
    S_GDATA32_ST    =  0x1008,  // Global data symbol
    S_PUB32_ST      =  0x1009,  // a public symbol (CV internal reserved)
    S_LPROC32_ST    =  0x100a,  // Local procedure start
    S_GPROC32_ST    =  0x100b,  // Global procedure start
    S_VFTABLE32     =  0x100c,  // address of virtual function table
    S_REGREL32_ST   =  0x100d,  // register relative address
    S_LTHREAD32_ST  =  0x100e,  // local thread storage
    S_GTHREAD32_ST  =  0x100f,  // global thread storage

    S_LPROCMIPS_ST  =  0x1010,  // Local procedure start
    S_GPROCMIPS_ST  =  0x1011,  // Global procedure start

    S_FRAMEPROC     =  0x1012,  // extra frame and proc information
    S_COMPILE2_ST   =  0x1013,  // extended compile flags and info

    // new symbols necessary for 16-bit enumerates of IA64 registers
    // and IA64 specific symbols

    S_MANYREG2_ST   =  0x1014,  // multiple register variable
    S_LPROCIA64_ST  =  0x1015,  // Local procedure start (IA64)
    S_GPROCIA64_ST  =  0x1016,  // Global procedure start (IA64)

    // Local symbols for IL
    S_LOCALSLOT_ST  =  0x1017,  // local IL sym with field for local slot index
    S_PARAMSLOT_ST  =  0x1018,  // local IL sym with field for parameter slot index

    S_ANNOTATION    =  0x1019,  // Annotation string literals

    // symbols to support managed code debugging
    S_GMANPROC_ST   =  0x101a,  // Global proc
    S_LMANPROC_ST   =  0x101b,  // Local proc
    S_RESERVED1     =  0x101c,  // reserved
    S_RESERVED2     =  0x101d,  // reserved
    S_RESERVED3     =  0x101e,  // reserved
    S_RESERVED4     =  0x101f,  // reserved
    S_LMANDATA_ST   =  0x1020,
    S_GMANDATA_ST   =  0x1021,
    S_MANFRAMEREL_ST=  0x1022,
    S_MANREGISTER_ST=  0x1023,
    S_MANSLOT_ST    =  0x1024,
    S_MANMANYREG_ST =  0x1025,
    S_MANREGREL_ST  =  0x1026,
    S_MANMANYREG2_ST=  0x1027,
    S_MANTYPREF     =  0x1028,  // Index for type referenced by name from metadata
    S_UNAMESPACE_ST =  0x1029,  // Using namespace

    // Symbols w/ SZ name fields. All name fields contain utf8 encoded strings.
    S_ST_MAX        =  0x1100,  // starting point for SZ name symbols

    S_OBJNAME       =  0x1101,  // path to object file name
    S_THUNK32       =  0x1102,  // Thunk Start
    S_BLOCK32       =  0x1103,  // block start
    S_WITH32        =  0x1104,  // with start
    S_LABEL32       =  0x1105,  // code label
    S_REGISTER      =  0x1106,  // Register variable
    S_CONSTANT      =  0x1107,  // constant symbol
    S_UDT           =  0x1108,  // User defined type
    S_COBOLUDT      =  0x1109,  // special UDT for cobol that does not symbol pack
    S_MANYREG       =  0x110a,  // multiple register variable
    S_BPREL32       =  0x110b,  // BP-relative
    S_LDATA32       =  0x110c,  // Module-local symbol
    S_GDATA32       =  0x110d,  // Global data symbol
    S_PUB32         =  0x110e,  // a public symbol (CV internal reserved)
    S_LPROC32       =  0x110f,  // Local procedure start
    S_GPROC32       =  0x1110,  // Global procedure start
    S_REGREL32      =  0x1111,  // register relative address
    S_LTHREAD32     =  0x1112,  // local thread storage
    S_GTHREAD32     =  0x1113,  // global thread storage

    S_LPROCMIPS     =  0x1114,  // Local procedure start
    S_GPROCMIPS     =  0x1115,  // Global procedure start
    S_COMPILE2      =  0x1116,  // extended compile flags and info
    S_MANYREG2      =  0x1117,  // multiple register variable
    S_LPROCIA64     =  0x1118,  // Local procedure start (IA64)
    S_GPROCIA64     =  0x1119,  // Global procedure start (IA64)
    S_LOCALSLOT     =  0x111a,  // local IL sym with field for local slot index
    S_SLOT          = S_LOCALSLOT,  // alias for LOCALSLOT
    S_PARAMSLOT     =  0x111b,  // local IL sym with field for parameter slot index

    // symbols to support managed code debugging
    S_LMANDATA      =  0x111c,
    S_GMANDATA      =  0x111d,
    S_MANFRAMEREL   =  0x111e,
    S_MANREGISTER   =  0x111f,
    S_MANSLOT       =  0x1120,
    S_MANMANYREG    =  0x1121,
    S_MANREGREL     =  0x1122,
    S_MANMANYREG2   =  0x1123,
    S_UNAMESPACE    =  0x1124,  // Using namespace

    // ref symbols with name fields
    S_PROCREF       =  0x1125,  // Reference to a procedure
    S_DATAREF       =  0x1126,  // Reference to data
    S_LPROCREF      =  0x1127,  // Local Reference to a procedure
    S_ANNOTATIONREF =  0x1128,  // Reference to an S_ANNOTATION symbol
    S_TOKENREF      =  0x1129,  // Reference to one of the many MANPROCSYM's

    // continuation of managed symbols
    S_GMANPROC      =  0x112a,  // Global proc
    S_LMANPROC      =  0x112b,  // Local proc

    // short, light-weight thunks
    S_TRAMPOLINE    =  0x112c,  // trampoline thunks
    S_MANCONSTANT   =  0x112d,  // constants with metadata type info

    // native attributed local/parms
    S_ATTR_FRAMEREL =  0x112e,  // relative to virtual frame ptr
    S_ATTR_REGISTER =  0x112f,  // stored in a register
    S_ATTR_REGREL   =  0x1130,  // relative to register (alternate frame ptr)
    S_ATTR_MANYREG  =  0x1131,  // stored in >1 register

    // Separated code (from the compiler) support
    S_SEPCODE       =  0x1132,

    S_LOCAL_2005    =  0x1133,  // defines a local symbol in optimized code
    S_DEFRANGE_2005 =  0x1134,  // defines a single range of addresses in which symbol can be evaluated
    S_DEFRANGE2_2005 =  0x1135,  // defines ranges of addresses in which symbol can be evaluated

    S_SECTION       =  0x1136,  // A COFF section in a PE executable
    S_COFFGROUP     =  0x1137,  // A COFF group
    S_EXPORT        =  0x1138,  // A export

    S_CALLSITEINFO  =  0x1139,  // Indirect call site information
    S_FRAMECOOKIE   =  0x113a,  // Security cookie information

    S_DISCARDED     =  0x113b,  // Discarded by LINK /OPT:REF (experimental, see richards)

    S_COMPILE3      =  0x113c,  // Replacement for S_COMPILE2
    S_ENVBLOCK      =  0x113d,  // Environment block split off from S_COMPILE2

    S_LOCAL         =  0x113e,  // defines a local symbol in optimized code
    S_DEFRANGE      =  0x113f,  // defines a single range of addresses in which symbol can be evaluated
    S_DEFRANGE_SUBFIELD =  0x1140,           // ranges for a subfield

    S_DEFRANGE_REGISTER =  0x1141,           // ranges for en-registered symbol
    S_DEFRANGE_FRAMEPOINTER_REL =  0x1142,   // range for stack symbol.
    S_DEFRANGE_SUBFIELD_REGISTER =  0x1143,  // ranges for en-registered field of symbol
    S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE =  0x1144, // range for stack symbol span valid full scope of function body, gap might apply.
    S_DEFRANGE_REGISTER_REL =  0x1145, // range for symbol address as register + offset.

    // S_PROC symbols that reference ID instead of type
    S_LPROC32_ID     =  0x1146,
    S_GPROC32_ID     =  0x1147,
    S_LPROCMIPS_ID   =  0x1148,
    S_GPROCMIPS_ID   =  0x1149,
    S_LPROCIA64_ID   =  0x114a,
    S_GPROCIA64_ID   =  0x114b,

    S_BUILDINFO      = 0x114c, // build information.
    S_INLINESITE     = 0x114d, // inlined function callsite.
    S_INLINESITE_END = 0x114e,
    S_PROC_ID_END    = 0x114f,

    S_DEFRANGE_HLSL  = 0x1150,
    S_GDATA_HLSL     = 0x1151,
    S_LDATA_HLSL     = 0x1152,

    S_FILESTATIC     = 0x1153,

#if defined(CC_DP_CXX) && CC_DP_CXX

    S_LOCAL_DPC_GROUPSHARED = 0x1154, // DPC groupshared variable
    S_LPROC32_DPC = 0x1155, // DPC local procedure start
    S_LPROC32_DPC_ID =  0x1156,
    S_DEFRANGE_DPC_PTR_TAG =  0x1157, // DPC pointer tag definition range
    S_DPC_SYM_TAG_MAP = 0x1158, // DPC pointer tag value to symbol record map

#endif // CC_DP_CXX
    
    S_ARMSWITCHTABLE  = 0x1159,
    S_CALLEES = 0x115a,
    S_CALLERS = 0x115b,
    S_POGODATA = 0x115c,
    S_INLINESITE2 = 0x115d,      // extended inline site information

    S_HEAPALLOCSITE = 0x115e,    // heap allocation site

    S_MOD_TYPEREF = 0x115f,      // only generated at link time

    S_REF_MINIPDB = 0x1160,      // only generated at link time for mini PDB
    S_PDBMAP      = 0x1161,      // only generated at link time for mini PDB

    S_GDATA_HLSL32 = 0x1162,
    S_LDATA_HLSL32 = 0x1163,

    S_GDATA_HLSL32_EX = 0x1164,
    S_LDATA_HLSL32_EX = 0x1165,

    S_RECTYPE_MAX,               // one greater than last
    S_RECTYPE_LAST  = S_RECTYPE_MAX - 1,
    S_RECTYPE_PAD   = S_RECTYPE_MAX + 0x100 // Used *only* to verify symbol record types so that current PDB code can potentially read
                                // future PDBs (assuming no format change, etc).

} SYM_ENUM_e;


//  enum describing compile flag ambient data model


typedef enum CV_CFL_DATA {
    CV_CFL_DNEAR    = 0x00,
    CV_CFL_DFAR     = 0x01,
    CV_CFL_DHUGE    = 0x02
} CV_CFL_DATA;




//  enum describing compile flag ambiant code model


typedef enum CV_CFL_CODE_e {
    CV_CFL_CNEAR    = 0x00,
    CV_CFL_CFAR     = 0x01,
    CV_CFL_CHUGE    = 0x02
} CV_CFL_CODE_e;




//  enum describing compile flag target floating point package

typedef enum CV_CFL_FPKG_e {
    CV_CFL_NDP      = 0x00,
    CV_CFL_EMU      = 0x01,
    CV_CFL_ALT      = 0x02
} CV_CFL_FPKG_e;


// enum describing function return method


typedef struct CV_PROCFLAGS {
    union {
        unsigned char   bAll;
        unsigned char   grfAll;
        struct {
            unsigned char CV_PFLAG_NOFPO     :1; // frame pointer present
            unsigned char CV_PFLAG_INT       :1; // interrupt return
            unsigned char CV_PFLAG_FAR       :1; // far return
            unsigned char CV_PFLAG_NEVER     :1; // function does not return
            unsigned char CV_PFLAG_NOTREACHED:1; // label isn't fallen into
            unsigned char CV_PFLAG_CUST_CALL :1; // custom calling convention
            unsigned char CV_PFLAG_NOINLINE  :1; // function marked as noinline
            unsigned char CV_PFLAG_OPTDBGINFO:1; // function has debug information for optimized code
        };
    };
} CV_PROCFLAGS;

// Extended proc flags
//
typedef struct CV_EXPROCFLAGS {
    CV_PROCFLAGS cvpf;
    union {
        unsigned char   grfAll;
        struct {
            unsigned char   __reserved_byte      :8; // must be zero
        };
    };
} CV_EXPROCFLAGS;

// local variable flags
typedef struct CV_LVARFLAGS {
    unsigned short fIsParam          :1; // variable is a parameter
    unsigned short fAddrTaken        :1; // address is taken
    unsigned short fCompGenx         :1; // variable is compiler generated
    unsigned short fIsAggregate      :1; // the symbol is splitted in temporaries,
                                         // which are treated by compiler as 
                                         // independent entities
    unsigned short fIsAggregated     :1; // Counterpart of fIsAggregate - tells
                                         // that it is a part of a fIsAggregate symbol
    unsigned short fIsAliased        :1; // variable has multiple simultaneous lifetimes
    unsigned short fIsAlias          :1; // represents one of the multiple simultaneous lifetimes
    unsigned short fIsRetValue       :1; // represents a function return value
    unsigned short fIsOptimizedOut   :1; // variable has no lifetimes
    unsigned short fIsEnregGlob      :1; // variable is an enregistered global
    unsigned short fIsEnregStat      :1; // variable is an enregistered static

    unsigned short unused            :5; // must be zero

} CV_LVARFLAGS;

// extended attributes common to all local variables
typedef struct CV_lvar_attr {
    CV_uoff32_t     off;        // first code address where var is live
    unsigned short  seg;
    CV_LVARFLAGS    flags;      // local var flags
} CV_lvar_attr;

// This is max length of a lexical linear IP range.
// The upper number are reserved for seeded and flow based range

#define CV_LEXICAL_RANGE_MAX  0xF000

// represents an address range, used for optimized code debug info

typedef struct CV_LVAR_ADDR_RANGE {       // defines a range of addresses
    CV_uoff32_t     offStart;
    unsigned short  isectStart;
    unsigned short  cbRange;
} CV_LVAR_ADDR_RANGE;

// Represents the holes in overall address range, all address is pre-bbt. 
// it is for compress and reduce the amount of relocations need.

typedef struct CV_LVAR_ADDR_GAP {
    unsigned short  gapStartOffset;   // relative offset from the beginning of the live range.
    unsigned short  cbRange;          // length of this gap.
} CV_LVAR_ADDR_GAP;

#if defined(CC_DP_CXX) && CC_DP_CXX

// Represents a mapping from a DPC pointer tag value to the corresponding symbol record
typedef struct CV_DPC_SYM_TAG_MAP_ENTRY {
    unsigned int tagValue;       // address taken symbol's pointer tag value.
    CV_off32_t  symRecordOffset; // offset of the symbol record from the S_LPROC32_DPC record it is nested within
} CV_DPC_SYM_TAG_MAP_ENTRY;

#endif // CC_DP_CXX

// enum describing function data return method

typedef enum CV_GENERIC_STYLE_e {
    CV_GENERIC_VOID   = 0x00,       // void return type
    CV_GENERIC_REG    = 0x01,       // return data is in registers
    CV_GENERIC_ICAN   = 0x02,       // indirect caller allocated near
    CV_GENERIC_ICAF   = 0x03,       // indirect caller allocated far
    CV_GENERIC_IRAN   = 0x04,       // indirect returnee allocated near
    CV_GENERIC_IRAF   = 0x05,       // indirect returnee allocated far
    CV_GENERIC_UNUSED = 0x06        // first unused
} CV_GENERIC_STYLE_e;


typedef struct CV_GENERIC_FLAG {
    unsigned short  cstyle  :1;     // true push varargs right to left
    unsigned short  rsclean :1;     // true if returnee stack cleanup
    unsigned short  unused  :14;    // unused
} CV_GENERIC_FLAG;


// flag bitfields for separated code attributes

typedef struct CV_SEPCODEFLAGS {
    unsigned long fIsLexicalScope : 1;     // S_SEPCODE doubles as lexical scope
    unsigned long fReturnsToParent : 1;    // code frag returns to parent
    unsigned long pad : 30;                // must be zero
} CV_SEPCODEFLAGS;

// Generic layout for symbol records

typedef struct SYMTYPE {
    unsigned short      reclen;     // Record length
    unsigned short      rectyp;     // Record type
    char                data[CV_ZEROLEN];
} SYMTYPE;

__INLINE SYMTYPE *NextSym (SYMTYPE * pSym) {
    return (SYMTYPE *) ((char *)pSym + pSym->reclen + sizeof(unsigned short));
}

//      non-model specific symbol types



typedef struct REGSYM_16t {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_REGISTER_16t
    CV_typ16_t      typind;     // Type index
    unsigned short  reg;        // register enumerate
    unsigned char   name[1];    // Length-prefixed name
} REGSYM_16t;

typedef struct REGSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_REGISTER
    CV_typ_t        typind;     // Type index or Metadata token
    unsigned short  reg;        // register enumerate
    unsigned char   name[1];    // Length-prefixed name
} REGSYM;

typedef struct ATTRREGSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANREGISTER | S_ATTR_REGISTER
    CV_typ_t        typind;     // Type index or Metadata token
    CV_lvar_attr    attr;       // local var attributes
    unsigned short  reg;        // register enumerate
    unsigned char   name[1];    // Length-prefixed name
} ATTRREGSYM;

typedef struct MANYREGSYM_16t {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANYREG_16t
    CV_typ16_t      typind;     // Type index
    unsigned char   count;      // count of number of registers
    unsigned char   reg[1];     // count register enumerates followed by
                                // length-prefixed name.  Registers are
                                // most significant first.
} MANYREGSYM_16t;

typedef struct MANYREGSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANYREG
    CV_typ_t        typind;     // Type index or metadata token
    unsigned char   count;      // count of number of registers
    unsigned char   reg[1];     // count register enumerates followed by
                                // length-prefixed name.  Registers are
                                // most significant first.
} MANYREGSYM;

typedef struct MANYREGSYM2 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANYREG2
    CV_typ_t        typind;     // Type index or metadata token
    unsigned short  count;      // count of number of registers
    unsigned short  reg[1];     // count register enumerates followed by
                                // length-prefixed name.  Registers are
                                // most significant first.
} MANYREGSYM2;

typedef struct ATTRMANYREGSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANMANYREG
    CV_typ_t        typind;     // Type index or metadata token
    CV_lvar_attr    attr;       // local var attributes
    unsigned char   count;      // count of number of registers
    unsigned char   reg[1];     // count register enumerates followed by
                                // length-prefixed name.  Registers are
                                // most significant first.
    unsigned char   name[CV_ZEROLEN];   // utf-8 encoded zero terminate name
} ATTRMANYREGSYM;

typedef struct ATTRMANYREGSYM2 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANMANYREG2 | S_ATTR_MANYREG
    CV_typ_t        typind;     // Type index or metadata token
    CV_lvar_attr    attr;       // local var attributes
    unsigned short  count;      // count of number of registers
    unsigned short  reg[1];     // count register enumerates followed by
                                // length-prefixed name.  Registers are
                                // most significant first.
    unsigned char   name[CV_ZEROLEN];   // utf-8 encoded zero terminate name
} ATTRMANYREGSYM2;

typedef struct CONSTSYM_16t {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_CONSTANT_16t
    CV_typ16_t      typind;     // Type index (containing enum if enumerate)
    unsigned short  value;      // numeric leaf containing value
    unsigned char   name[CV_ZEROLEN];     // Length-prefixed name
} CONSTSYM_16t;

typedef struct CONSTSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_CONSTANT or S_MANCONSTANT
    CV_typ_t        typind;     // Type index (containing enum if enumerate) or metadata token
    unsigned short  value;      // numeric leaf containing value
    unsigned char   name[CV_ZEROLEN];     // Length-prefixed name
} CONSTSYM;


typedef struct UDTSYM_16t {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_UDT_16t | S_COBOLUDT_16t
    CV_typ16_t      typind;     // Type index
    unsigned char   name[1];    // Length-prefixed name
} UDTSYM_16t;


typedef struct UDTSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_UDT | S_COBOLUDT
    CV_typ_t        typind;     // Type index
    unsigned char   name[1];    // Length-prefixed name
} UDTSYM;

typedef struct MANTYPREF {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANTYPREF
    CV_typ_t        typind;     // Type index
} MANTYPREF;

typedef struct SEARCHSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_SSEARCH
    unsigned long   startsym;   // offset of the procedure
    unsigned short  seg;        // segment of symbol
} SEARCHSYM;


typedef struct CFLAGSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_COMPILE
    unsigned char   machine;    // target processor
    struct  {
        unsigned char   language    :8; // language index
        unsigned char   pcode       :1; // true if pcode present
        unsigned char   floatprec   :2; // floating precision
        unsigned char   floatpkg    :2; // float package
        unsigned char   ambdata     :3; // ambient data model
        unsigned char   ambcode     :3; // ambient code model
        unsigned char   mode32      :1; // true if compiled 32 bit mode
        unsigned char   pad         :4; // reserved
    } flags;
    unsigned char       ver[1];     // Length-prefixed compiler version string
} CFLAGSYM;


typedef struct COMPILESYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_COMPILE2
    struct {
        unsigned long   iLanguage       :  8;   // language index
        unsigned long   fEC             :  1;   // compiled for E/C
        unsigned long   fNoDbgInfo      :  1;   // not compiled with debug info
        unsigned long   fLTCG           :  1;   // compiled with LTCG
        unsigned long   fNoDataAlign    :  1;   // compiled with -Bzalign
        unsigned long   fManagedPresent :  1;   // managed code/data present
        unsigned long   fSecurityChecks :  1;   // compiled with /GS
        unsigned long   fHotPatch       :  1;   // compiled with /hotpatch
        unsigned long   fCVTCIL         :  1;   // converted with CVTCIL
        unsigned long   fMSILModule     :  1;   // MSIL netmodule
        unsigned long   pad             : 15;   // reserved, must be 0
    } flags;
    unsigned short  machine;    // target processor
    unsigned short  verFEMajor; // front end major version #
    unsigned short  verFEMinor; // front end minor version #
    unsigned short  verFEBuild; // front end build version #
    unsigned short  verMajor;   // back end major version #
    unsigned short  verMinor;   // back end minor version #
    unsigned short  verBuild;   // back end build version #
    unsigned char   verSt[1];   // Length-prefixed compiler version string, followed
                                //  by an optional block of zero terminated strings
                                //  terminated with a double zero.
} COMPILESYM;

typedef struct COMPILESYM3 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_COMPILE3
    struct {
        unsigned long   iLanguage       :  8;   // language index
        unsigned long   fEC             :  1;   // compiled for E/C
        unsigned long   fNoDbgInfo      :  1;   // not compiled with debug info
        unsigned long   fLTCG           :  1;   // compiled with LTCG
        unsigned long   fNoDataAlign    :  1;   // compiled with -Bzalign
        unsigned long   fManagedPresent :  1;   // managed code/data present
        unsigned long   fSecurityChecks :  1;   // compiled with /GS
        unsigned long   fHotPatch       :  1;   // compiled with /hotpatch
        unsigned long   fCVTCIL         :  1;   // converted with CVTCIL
        unsigned long   fMSILModule     :  1;   // MSIL netmodule
        unsigned long   fSdl            :  1;   // compiled with /sdl
        unsigned long   fPGO            :  1;   // compiled with /ltcg:pgo or pgu
        unsigned long   fExp            :  1;   // .exp module
        unsigned long   pad             : 12;   // reserved, must be 0
    } flags;
    unsigned short  machine;    // target processor
    unsigned short  verFEMajor; // front end major version #
    unsigned short  verFEMinor; // front end minor version #
    unsigned short  verFEBuild; // front end build version #
    unsigned short  verFEQFE;   // front end QFE version #
    unsigned short  verMajor;   // back end major version #
    unsigned short  verMinor;   // back end minor version #
    unsigned short  verBuild;   // back end build version #
    unsigned short  verQFE;     // back end QFE version #
    char            verSz[1];   // Zero terminated compiler version string
} COMPILESYM3;

typedef struct ENVBLOCKSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_ENVBLOCK
    struct {
        unsigned char  rev              : 1;    // reserved
        unsigned char  pad              : 7;    // reserved, must be 0
    } flags;
    unsigned char   rgsz[1];    // Sequence of zero-terminated strings
} ENVBLOCKSYM;

typedef struct OBJNAMESYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_OBJNAME
    unsigned long   signature;  // signature
    unsigned char   name[1];    // Length-prefixed name
} OBJNAMESYM;


typedef struct ENDARGSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_ENDARG
} ENDARGSYM;


typedef struct RETURNSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_RETURN
    CV_GENERIC_FLAG flags;      // flags
    unsigned char   style;      // CV_GENERIC_STYLE_e return style
                                // followed by return method data
} RETURNSYM;


typedef struct ENTRYTHISSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_ENTRYTHIS
    unsigned char   thissym;    // symbol describing this pointer on entry
} ENTRYTHISSYM;


//      symbol types for 16:16 memory model


typedef struct BPRELSYM16 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_BPREL16
    CV_off16_t      off;        // BP-relative offset
    CV_typ16_t      typind;     // Type index
    unsigned char   name[1];    // Length-prefixed name
} BPRELSYM16;


typedef struct DATASYM16 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_LDATA or S_GDATA
    CV_uoff16_t     off;        // offset of symbol
    unsigned short  seg;        // segment of symbol
    CV_typ16_t      typind;     // Type index
    unsigned char   name[1];    // Length-prefixed name
} DATASYM16;
typedef DATASYM16 PUBSYM16;


typedef struct PROCSYM16 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GPROC16 or S_LPROC16
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    unsigned short  len;        // Proc length
    unsigned short  DbgStart;   // Debug start offset
    unsigned short  DbgEnd;     // Debug end offset
    CV_uoff16_t     off;        // offset of symbol
    unsigned short  seg;        // segment of symbol
    CV_typ16_t      typind;     // Type index
    CV_PROCFLAGS    flags;      // Proc flags
    unsigned char   name[1];    // Length-prefixed name
} PROCSYM16;


typedef struct THUNKSYM16 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_THUNK
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    CV_uoff16_t     off;        // offset of symbol
    unsigned short  seg;        // segment of symbol
    unsigned short  len;        // length of thunk
    unsigned char   ord;        // THUNK_ORDINAL specifying type of thunk
    unsigned char   name[1];    // name of thunk
    unsigned char   variant[CV_ZEROLEN]; // variant portion of thunk
} THUNKSYM16;

typedef struct LABELSYM16 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_LABEL16
    CV_uoff16_t     off;        // offset of symbol
    unsigned short  seg;        // segment of symbol
    CV_PROCFLAGS    flags;      // flags
    unsigned char   name[1];    // Length-prefixed name
} LABELSYM16;


typedef struct BLOCKSYM16 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_BLOCK16
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned short  len;        // Block length
    CV_uoff16_t     off;        // offset of symbol
    unsigned short  seg;        // segment of symbol
    unsigned char   name[1];    // Length-prefixed name
} BLOCKSYM16;


typedef struct WITHSYM16 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_WITH16
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned short  len;        // Block length
    CV_uoff16_t     off;        // offset of symbol
    unsigned short  seg;        // segment of symbol
    unsigned char   expr[1];    // Length-prefixed expression
} WITHSYM16;


typedef enum CEXM_MODEL_e {
    CEXM_MDL_table          = 0x00, // not executable
    CEXM_MDL_jumptable      = 0x01, // Compiler generated jump table
    CEXM_MDL_datapad        = 0x02, // Data padding for alignment
    CEXM_MDL_native         = 0x20, // native (actually not-pcode)
    CEXM_MDL_cobol          = 0x21, // cobol
    CEXM_MDL_codepad        = 0x22, // Code padding for alignment
    CEXM_MDL_code           = 0x23, // code
    CEXM_MDL_sql            = 0x30, // sql
    CEXM_MDL_pcode          = 0x40, // pcode
    CEXM_MDL_pcode32Mac     = 0x41, // macintosh 32 bit pcode
    CEXM_MDL_pcode32MacNep  = 0x42, // macintosh 32 bit pcode native entry point
    CEXM_MDL_javaInt        = 0x50,
    CEXM_MDL_unknown        = 0xff
} CEXM_MODEL_e;

// use the correct enumerate name
#define CEXM_MDL_SQL CEXM_MDL_sql

typedef enum CV_COBOL_e {
    CV_COBOL_dontstop,
    CV_COBOL_pfm,
    CV_COBOL_false,
    CV_COBOL_extcall
} CV_COBOL_e;

typedef struct CEXMSYM16 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_CEXMODEL16
    CV_uoff16_t     off;        // offset of symbol
    unsigned short  seg;        // segment of symbol
    unsigned short  model;      // execution model
    union {
        struct  {
            CV_uoff16_t pcdtable;   // offset to pcode function table
            CV_uoff16_t pcdspi;     // offset to segment pcode information
        } pcode;
        struct {
            unsigned short  subtype;   // see CV_COBOL_e above
            unsigned short  flag;
        } cobol;
    };
} CEXMSYM16;


typedef struct VPATHSYM16 {
    unsigned short  reclen;     // record length
    unsigned short  rectyp;     // S_VFTPATH16
    CV_uoff16_t     off;        // offset of virtual function table
    unsigned short  seg;        // segment of virtual function table
    CV_typ16_t      root;       // type index of the root of path
    CV_typ16_t      path;       // type index of the path record
} VPATHSYM16;


typedef struct REGREL16 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_REGREL16
    CV_uoff16_t     off;        // offset of symbol
    unsigned short  reg;        // register index
    CV_typ16_t      typind;     // Type index
    unsigned char   name[1];    // Length-prefixed name
} REGREL16;


typedef struct BPRELSYM32_16t {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_BPREL32_16t
    CV_off32_t      off;        // BP-relative offset
    CV_typ16_t      typind;     // Type index
    unsigned char   name[1];    // Length-prefixed name
} BPRELSYM32_16t;

typedef struct BPRELSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_BPREL32
    CV_off32_t      off;        // BP-relative offset
    CV_typ_t        typind;     // Type index or Metadata token
    unsigned char   name[1];    // Length-prefixed name
} BPRELSYM32;

typedef struct FRAMERELSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANFRAMEREL | S_ATTR_FRAMEREL
    CV_off32_t      off;        // Frame relative offset
    CV_typ_t        typind;     // Type index or Metadata token
    CV_lvar_attr    attr;       // local var attributes
    unsigned char   name[1];    // Length-prefixed name
} FRAMERELSYM;

typedef FRAMERELSYM ATTRFRAMERELSYM;


typedef struct SLOTSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_LOCALSLOT or S_PARAMSLOT
    unsigned long   iSlot;      // slot index
    CV_typ_t        typind;     // Type index or Metadata token
    unsigned char   name[1];    // Length-prefixed name
} SLOTSYM32;

typedef struct ATTRSLOTSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANSLOT
    unsigned long   iSlot;      // slot index
    CV_typ_t        typind;     // Type index or Metadata token
    CV_lvar_attr    attr;       // local var attributes
    unsigned char   name[1];    // Length-prefixed name
} ATTRSLOTSYM;

typedef struct ANNOTATIONSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_ANNOTATION
    CV_uoff32_t     off;
    unsigned short  seg;
    unsigned short  csz;        // Count of zero terminated annotation strings
    unsigned char   rgsz[1];    // Sequence of zero terminated annotation strings
} ANNOTATIONSYM;

typedef struct DATASYM32_16t {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_LDATA32_16t, S_GDATA32_16t or S_PUB32_16t
    CV_uoff32_t     off;
    unsigned short  seg;
    CV_typ16_t      typind;     // Type index
    unsigned char   name[1];    // Length-prefixed name
} DATASYM32_16t;
typedef DATASYM32_16t PUBSYM32_16t;

typedef struct DATASYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_LDATA32, S_GDATA32, S_LMANDATA, S_GMANDATA
    CV_typ_t        typind;     // Type index, or Metadata token if a managed symbol
    CV_uoff32_t     off;
    unsigned short  seg;
    unsigned char   name[1];    // Length-prefixed name
} DATASYM32;

typedef struct DATASYMHLSL {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GDATA_HLSL, S_LDATA_HLSL
    CV_typ_t        typind;     // Type index
    unsigned short  regType;    // register type from CV_HLSLREG_e
    unsigned short  dataslot;   // Base data (cbuffer, groupshared, etc.) slot
    unsigned short  dataoff;    // Base data byte offset start
    unsigned short  texslot;    // Texture slot start
    unsigned short  sampslot;   // Sampler slot start
    unsigned short  uavslot;    // UAV slot start
    unsigned char   name[1];    // name
} DATASYMHLSL;

typedef struct DATASYMHLSL32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GDATA_HLSL32, S_LDATA_HLSL32
    CV_typ_t        typind;     // Type index
    unsigned long   dataslot;   // Base data (cbuffer, groupshared, etc.) slot
    unsigned long   dataoff;    // Base data byte offset start
    unsigned long   texslot;    // Texture slot start
    unsigned long   sampslot;   // Sampler slot start
    unsigned long   uavslot;    // UAV slot start
    unsigned short  regType;    // register type from CV_HLSLREG_e
    unsigned char   name[1];    // name
} DATASYMHLSL32;

typedef struct DATASYMHLSL32_EX {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GDATA_HLSL32_EX, S_LDATA_HLSL32_EX
    CV_typ_t        typind;     // Type index
    unsigned long   regID;      // Register index
    unsigned long   dataoff;    // Base data byte offset start
    unsigned long   bindSpace;  // Binding space
    unsigned long   bindSlot;   // Lower bound in binding space
    unsigned short  regType;    // register type from CV_HLSLREG_e
    unsigned char   name[1];    // name
} DATASYMHLSL32_EX;

typedef enum CV_PUBSYMFLAGS_e
 {
    cvpsfNone     = 0,
    cvpsfCode     = 0x00000001,
    cvpsfFunction = 0x00000002,
    cvpsfManaged  = 0x00000004,
    cvpsfMSIL     = 0x00000008,
} CV_PUBSYMFLAGS_e;

typedef union CV_PUBSYMFLAGS {
    CV_pubsymflag_t grfFlags;
    struct {
        CV_pubsymflag_t fCode       :  1;    // set if public symbol refers to a code address
        CV_pubsymflag_t fFunction   :  1;    // set if public symbol is a function
        CV_pubsymflag_t fManaged    :  1;    // set if managed code (native or IL)
        CV_pubsymflag_t fMSIL       :  1;    // set if managed IL code
        CV_pubsymflag_t __unused    : 28;    // must be zero
    };
} CV_PUBSYMFLAGS;

typedef struct PUBSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_PUB32
    CV_PUBSYMFLAGS  pubsymflags;
    CV_uoff32_t     off;
    unsigned short  seg;
    unsigned char   name[1];    // Length-prefixed name
} PUBSYM32;


typedef struct PROCSYM32_16t {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GPROC32_16t or S_LPROC32_16t
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    unsigned long   len;        // Proc length
    unsigned long   DbgStart;   // Debug start offset
    unsigned long   DbgEnd;     // Debug end offset
    CV_uoff32_t     off;
    unsigned short  seg;
    CV_typ16_t      typind;     // Type index
    CV_PROCFLAGS    flags;      // Proc flags
    unsigned char   name[1];    // Length-prefixed name
} PROCSYM32_16t;

typedef struct PROCSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GPROC32, S_LPROC32, S_GPROC32_ID, S_LPROC32_ID, S_LPROC32_DPC or S_LPROC32_DPC_ID
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    unsigned long   len;        // Proc length
    unsigned long   DbgStart;   // Debug start offset
    unsigned long   DbgEnd;     // Debug end offset
    CV_typ_t        typind;     // Type index or ID
    CV_uoff32_t     off;
    unsigned short  seg;
    CV_PROCFLAGS    flags;      // Proc flags
    unsigned char   name[1];    // Length-prefixed name
} PROCSYM32;

typedef struct MANPROCSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GMANPROC, S_LMANPROC, S_GMANPROCIA64 or S_LMANPROCIA64
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    unsigned long   len;        // Proc length
    unsigned long   DbgStart;   // Debug start offset
    unsigned long   DbgEnd;     // Debug end offset
    CV_tkn_t        token;      // COM+ metadata token for method
    CV_uoff32_t     off;
    unsigned short  seg;
    CV_PROCFLAGS    flags;      // Proc flags
    unsigned short  retReg;     // Register return value is in (may not be used for all archs)
    unsigned char   name[1];    // optional name field
} MANPROCSYM;

typedef struct MANPROCSYMMIPS {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GMANPROCMIPS or S_LMANPROCMIPS
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    unsigned long   len;        // Proc length
    unsigned long   DbgStart;   // Debug start offset
    unsigned long   DbgEnd;     // Debug end offset
    unsigned long   regSave;    // int register save mask
    unsigned long   fpSave;     // fp register save mask
    CV_uoff32_t     intOff;     // int register save offset
    CV_uoff32_t     fpOff;      // fp register save offset
    CV_tkn_t        token;      // COM+ token type
    CV_uoff32_t     off;
    unsigned short  seg;
    unsigned char   retReg;     // Register return value is in
    unsigned char   frameReg;   // Frame pointer register
    unsigned char   name[1];    // optional name field
} MANPROCSYMMIPS;

typedef struct THUNKSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_THUNK32
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    CV_uoff32_t     off;
    unsigned short  seg;
    unsigned short  len;        // length of thunk
    unsigned char   ord;        // THUNK_ORDINAL specifying type of thunk
    unsigned char   name[1];    // Length-prefixed name
    unsigned char   variant[CV_ZEROLEN]; // variant portion of thunk
} THUNKSYM32;

typedef enum TRAMP_e {      // Trampoline subtype
    trampIncremental,           // incremental thunks
    trampBranchIsland,          // Branch island thunks
} TRAMP_e;

typedef struct TRAMPOLINESYM {  // Trampoline thunk symbol
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_TRAMPOLINE
    unsigned short  trampType;  // trampoline sym subtype
    unsigned short  cbThunk;    // size of the thunk
    CV_uoff32_t     offThunk;   // offset of the thunk
    CV_uoff32_t     offTarget;  // offset of the target of the thunk
    unsigned short  sectThunk;  // section index of the thunk
    unsigned short  sectTarget; // section index of the target of the thunk
} TRAMPOLINE;

typedef struct LABELSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_LABEL32
    CV_uoff32_t     off;
    unsigned short  seg;
    CV_PROCFLAGS    flags;      // flags
    unsigned char   name[1];    // Length-prefixed name
} LABELSYM32;


typedef struct BLOCKSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_BLOCK32
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   len;        // Block length
    CV_uoff32_t     off;        // Offset in code segment
    unsigned short  seg;        // segment of label
    unsigned char   name[1];    // Length-prefixed name
} BLOCKSYM32;


typedef struct WITHSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_WITH32
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   len;        // Block length
    CV_uoff32_t     off;        // Offset in code segment
    unsigned short  seg;        // segment of label
    unsigned char   expr[1];    // Length-prefixed expression string
} WITHSYM32;



typedef struct CEXMSYM32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_CEXMODEL32
    CV_uoff32_t     off;        // offset of symbol
    unsigned short  seg;        // segment of symbol
    unsigned short  model;      // execution model
    union {
        struct  {
            CV_uoff32_t pcdtable;   // offset to pcode function table
            CV_uoff32_t pcdspi;     // offset to segment pcode information
        } pcode;
        struct {
            unsigned short  subtype;   // see CV_COBOL_e above
            unsigned short  flag;
        } cobol;
        struct {
            CV_uoff32_t calltableOff; // offset to function table
            unsigned short calltableSeg; // segment of function table
        } pcode32Mac;
    };
} CEXMSYM32;



typedef struct VPATHSYM32_16t {
    unsigned short  reclen;     // record length
    unsigned short  rectyp;     // S_VFTABLE32_16t
    CV_uoff32_t     off;        // offset of virtual function table
    unsigned short  seg;        // segment of virtual function table
    CV_typ16_t      root;       // type index of the root of path
    CV_typ16_t      path;       // type index of the path record
} VPATHSYM32_16t;

typedef struct VPATHSYM32 {
    unsigned short  reclen;     // record length
    unsigned short  rectyp;     // S_VFTABLE32
    CV_typ_t        root;       // type index of the root of path
    CV_typ_t        path;       // type index of the path record
    CV_uoff32_t     off;        // offset of virtual function table
    unsigned short  seg;        // segment of virtual function table
} VPATHSYM32;





typedef struct REGREL32_16t {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_REGREL32_16t
    CV_uoff32_t     off;        // offset of symbol
    unsigned short  reg;        // register index for symbol
    CV_typ16_t      typind;     // Type index
    unsigned char   name[1];    // Length-prefixed name
} REGREL32_16t;

typedef struct REGREL32 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_REGREL32
    CV_uoff32_t     off;        // offset of symbol
    CV_typ_t        typind;     // Type index or metadata token
    unsigned short  reg;        // register index for symbol
    unsigned char   name[1];    // Length-prefixed name
} REGREL32;

typedef struct ATTRREGREL {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_MANREGREL | S_ATTR_REGREL
    CV_uoff32_t     off;        // offset of symbol
    CV_typ_t        typind;     // Type index or metadata token
    unsigned short  reg;        // register index for symbol
    CV_lvar_attr    attr;       // local var attributes
    unsigned char   name[1];    // Length-prefixed name
} ATTRREGREL;

typedef ATTRREGREL  ATTRREGRELSYM;

typedef struct THREADSYM32_16t {
    unsigned short  reclen;     // record length
    unsigned short  rectyp;     // S_LTHREAD32_16t | S_GTHREAD32_16t
    CV_uoff32_t     off;        // offset into thread storage
    unsigned short  seg;        // segment of thread storage
    CV_typ16_t      typind;     // type index
    unsigned char   name[1];    // length prefixed name
} THREADSYM32_16t;

typedef struct THREADSYM32 {
    unsigned short  reclen;     // record length
    unsigned short  rectyp;     // S_LTHREAD32 | S_GTHREAD32
    CV_typ_t        typind;     // type index
    CV_uoff32_t     off;        // offset into thread storage
    unsigned short  seg;        // segment of thread storage
    unsigned char   name[1];    // length prefixed name
} THREADSYM32;

typedef struct SLINK32 {
    unsigned short  reclen;     // record length
    unsigned short  rectyp;     // S_SLINK32
    unsigned long   framesize;  // frame size of parent procedure
    CV_off32_t      off;        // signed offset where the static link was saved relative to the value of reg
    unsigned short  reg;
} SLINK32;

typedef struct PROCSYMMIPS_16t {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GPROCMIPS_16t or S_LPROCMIPS_16t
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    unsigned long   len;        // Proc length
    unsigned long   DbgStart;   // Debug start offset
    unsigned long   DbgEnd;     // Debug end offset
    unsigned long   regSave;    // int register save mask
    unsigned long   fpSave;     // fp register save mask
    CV_uoff32_t     intOff;     // int register save offset
    CV_uoff32_t     fpOff;      // fp register save offset
    CV_uoff32_t     off;        // Symbol offset
    unsigned short  seg;        // Symbol segment
    CV_typ16_t      typind;     // Type index
    unsigned char   retReg;     // Register return value is in
    unsigned char   frameReg;   // Frame pointer register
    unsigned char   name[1];    // Length-prefixed name
} PROCSYMMIPS_16t;

typedef struct PROCSYMMIPS {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GPROCMIPS or S_LPROCMIPS
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    unsigned long   len;        // Proc length
    unsigned long   DbgStart;   // Debug start offset
    unsigned long   DbgEnd;     // Debug end offset
    unsigned long   regSave;    // int register save mask
    unsigned long   fpSave;     // fp register save mask
    CV_uoff32_t     intOff;     // int register save offset
    CV_uoff32_t     fpOff;      // fp register save offset
    CV_typ_t        typind;     // Type index
    CV_uoff32_t     off;        // Symbol offset
    unsigned short  seg;        // Symbol segment
    unsigned char   retReg;     // Register return value is in
    unsigned char   frameReg;   // Frame pointer register
    unsigned char   name[1];    // Length-prefixed name
} PROCSYMMIPS;

typedef struct PROCSYMIA64 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GPROCIA64 or S_LPROCIA64
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
    unsigned long   len;        // Proc length
    unsigned long   DbgStart;   // Debug start offset
    unsigned long   DbgEnd;     // Debug end offset
    CV_typ_t        typind;     // Type index
    CV_uoff32_t     off;        // Symbol offset
    unsigned short  seg;        // Symbol segment
    unsigned short  retReg;     // Register return value is in
    CV_PROCFLAGS    flags;      // Proc flags
    unsigned char   name[1];    // Length-prefixed name
} PROCSYMIA64;

typedef struct REFSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_PROCREF_ST, S_DATAREF_ST, or S_LPROCREF_ST
    unsigned long   sumName;    // SUC of the name
    unsigned long   ibSym;      // Offset of actual symbol in $$Symbols
    unsigned short  imod;       // Module containing the actual symbol
    unsigned short  usFill;     // align this record
} REFSYM;

typedef struct REFSYM2 {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_PROCREF, S_DATAREF, or S_LPROCREF
    unsigned long   sumName;    // SUC of the name
    unsigned long   ibSym;      // Offset of actual symbol in $$Symbols
    unsigned short  imod;       // Module containing the actual symbol
    unsigned char   name[1];    // hidden name made a first class member
} REFSYM2;

typedef struct ALIGNSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_ALIGN
} ALIGNSYM;

typedef struct OEMSYMBOL {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_OEM
    unsigned char   idOem[16];  // an oem ID (GUID)
    CV_typ_t        typind;     // Type index
    unsigned long   rgl[];      // user data, force 4-byte alignment
} OEMSYMBOL;

//  generic block definition symbols
//  these are similar to the equivalent 16:16 or 16:32 symbols but
//  only define the length, type and linkage fields

typedef struct PROCSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_GPROC16 or S_LPROC16
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
} PROCSYM;


typedef struct THUNKSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_THUNK
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
    unsigned long   pNext;      // pointer to next symbol
} THUNKSYM;

typedef struct BLOCKSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_BLOCK16
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
} BLOCKSYM;


typedef struct WITHSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_WITH16
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this blocks end
} WITHSYM;

typedef struct FRAMEPROCSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_FRAMEPROC
    unsigned long   cbFrame;    // count of bytes of total frame of procedure
    unsigned long   cbPad;      // count of bytes of padding in the frame
    CV_uoff32_t     offPad;     // offset (relative to frame poniter) to where
                                //  padding starts
    unsigned long   cbSaveRegs; // count of bytes of callee save registers
    CV_uoff32_t     offExHdlr;  // offset of exception handler
    unsigned short  sectExHdlr; // section id of exception handler

    struct {
        unsigned long   fHasAlloca  :  1;   // function uses _alloca()
        unsigned long   fHasSetJmp  :  1;   // function uses setjmp()
        unsigned long   fHasLongJmp :  1;   // function uses longjmp()
        unsigned long   fHasInlAsm  :  1;   // function uses inline asm
        unsigned long   fHasEH      :  1;   // function has EH states
        unsigned long   fInlSpec    :  1;   // function was speced as inline
        unsigned long   fHasSEH     :  1;   // function has SEH
        unsigned long   fNaked      :  1;   // function is __declspec(naked)
        unsigned long   fSecurityChecks :  1;   // function has buffer security check introduced by /GS.
        unsigned long   fAsyncEH    :  1;   // function compiled with /EHa
        unsigned long   fGSNoStackOrdering :  1;   // function has /GS buffer checks, but stack ordering couldn't be done
        unsigned long   fWasInlined :  1;   // function was inlined within another function
        unsigned long   fGSCheck    :  1;   // function is __declspec(strict_gs_check)
        unsigned long   fSafeBuffers : 1;   // function is __declspec(safebuffers)
        unsigned long   encodedLocalBasePointer : 2;  // record function's local pointer explicitly.
        unsigned long   encodedParamBasePointer : 2;  // record function's parameter pointer explicitly.
        unsigned long   fPogoOn      : 1;   // function was compiled with PGO/PGU
        unsigned long   fValidCounts : 1;   // Do we have valid Pogo counts?
        unsigned long   fOptSpeed    : 1;  // Did we optimize for speed?
        unsigned long   fGuardCF    :  1;   // function contains CFG checks (and no write checks)
        unsigned long   fGuardCFW   :  1;   // function contains CFW checks and/or instrumentation
        unsigned long   pad          : 9;   // must be zero
    } flags;
} FRAMEPROCSYM;

#ifdef  __cplusplus
namespace CodeViewInfo 
{
__inline unsigned short ExpandEncodedBasePointerReg(unsigned machineType, unsigned encodedFrameReg) 
{
    static const unsigned short rgFramePointerRegX86[] = {
        CV_REG_NONE, CV_ALLREG_VFRAME, CV_REG_EBP, CV_REG_EBX};
    static const unsigned short rgFramePointerRegX64[] = {
        CV_REG_NONE, CV_AMD64_RSP, CV_AMD64_RBP, CV_AMD64_R13};
    static const unsigned short rgFramePointerRegArm[] = {
        CV_REG_NONE, CV_ARM_SP, CV_ARM_R7, CV_REG_NONE};

    if (encodedFrameReg >= 4) {
        return CV_REG_NONE;
    }
    switch (machineType) {
        case CV_CFL_8080 :
        case CV_CFL_8086 :
        case CV_CFL_80286 :
        case CV_CFL_80386 :
        case CV_CFL_80486 :
        case CV_CFL_PENTIUM :
        case CV_CFL_PENTIUMII :
        case CV_CFL_PENTIUMIII :
            return rgFramePointerRegX86[encodedFrameReg];
        case CV_CFL_AMD64 :
            return rgFramePointerRegX64[encodedFrameReg];
        case CV_CFL_ARMNT :
            return rgFramePointerRegArm[encodedFrameReg];
        default:
            return CV_REG_NONE;
    }
}
}
#endif

typedef struct UNAMESPACE {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_UNAMESPACE
    unsigned char   name[1];    // name
} UNAMESPACE;

typedef struct SEPCODESYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_SEPCODE
    unsigned long   pParent;    // pointer to the parent
    unsigned long   pEnd;       // pointer to this block's end
    unsigned long   length;     // count of bytes of this block
    CV_SEPCODEFLAGS scf;        // flags
    CV_uoff32_t     off;        // sect:off of the separated code
    CV_uoff32_t     offParent;  // sectParent:offParent of the enclosing scope
    unsigned short  sect;       //  (proc, block, or sepcode)
    unsigned short  sectParent;
} SEPCODESYM;

typedef struct BUILDINFOSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_BUILDINFO
    CV_ItemId       id;         // CV_ItemId of Build Info.
} BUILDINFOSYM;

typedef struct INLINESITESYM {
    unsigned short  reclen;    // Record length
    unsigned short  rectyp;    // S_INLINESITE
    unsigned long   pParent;   // pointer to the inliner
    unsigned long   pEnd;      // pointer to this block's end
    CV_ItemId       inlinee;   // CV_ItemId of inlinee
    unsigned char   binaryAnnotations[CV_ZEROLEN];   // an array of compressed binary annotations.
} INLINESITESYM;

typedef struct INLINESITESYM2 {
    unsigned short  reclen;         // Record length
    unsigned short  rectyp;         // S_INLINESITE2
    unsigned long   pParent;        // pointer to the inliner
    unsigned long   pEnd;           // pointer to this block's end
    CV_ItemId       inlinee;        // CV_ItemId of inlinee
    unsigned long   invocations;    // entry count
    unsigned char   binaryAnnotations[CV_ZEROLEN];   // an array of compressed binary annotations.
} INLINESITESYM2;


// Defines a locals and it is live range, how to evaluate.
// S_DEFRANGE modifies previous local S_LOCAL, it has to consecutive.

typedef struct LOCALSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_LOCAL
    CV_typ_t        typind;     // type index   
    CV_LVARFLAGS    flags;      // local var flags

    unsigned char   name[CV_ZEROLEN];   // Name of this symbol, a null terminated array of UTF8 characters.
} LOCALSYM;

typedef struct FILESTATICSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_FILESTATIC
    CV_typ_t        typind;     // type index   
    CV_uoff32_t     modOffset;  // index of mod filename in stringtable
    CV_LVARFLAGS    flags;      // local var flags

    unsigned char   name[CV_ZEROLEN];   // Name of this symbol, a null terminated array of UTF8 characters
} FILESTATICSYM;

typedef struct DEFRANGESYM {    // A live range of sub field of variable
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_DEFRANGE

    CV_uoff32_t     program;    // DIA program to evaluate the value of the symbol

    CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
    CV_LVAR_ADDR_GAP   gaps[CV_ZEROLEN];  // The value is not available in following gaps. 
} DEFRANGESYM;

typedef struct DEFRANGESYMSUBFIELD { // A live range of sub field of variable. like locala.i
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_DEFRANGE_SUBFIELD

    CV_uoff32_t     program;    // DIA program to evaluate the value of the symbol

    CV_uoff32_t     offParent;  // Offset in parent variable.

    CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
    CV_LVAR_ADDR_GAP   gaps[CV_ZEROLEN];  // The value is not available in following gaps. 
} DEFRANGESYMSUBFIELD;

typedef struct CV_RANGEATTR {
    unsigned short  maybe : 1;    // May have no user name on one of control flow path.
    unsigned short  padding : 15; // Padding for future use.
} CV_RANGEATTR;

typedef struct DEFRANGESYMREGISTER {    // A live range of en-registed variable
    unsigned short     reclen;     // Record length
    unsigned short     rectyp;     // S_DEFRANGE_REGISTER 
    unsigned short     reg;        // Register to hold the value of the symbol
    CV_RANGEATTR       attr;       // Attribute of the register range.
    CV_LVAR_ADDR_RANGE range;      // Range of addresses where this program is valid
    CV_LVAR_ADDR_GAP   gaps[CV_ZEROLEN];  // The value is not available in following gaps. 
} DEFRANGESYMREGISTER;

typedef struct DEFRANGESYMFRAMEPOINTERREL {    // A live range of frame variable
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_DEFRANGE_FRAMEPOINTER_REL

    CV_off32_t      offFramePointer;  // offset to frame pointer

    CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
    CV_LVAR_ADDR_GAP   gaps[CV_ZEROLEN];  // The value is not available in following gaps. 
} DEFRANGESYMFRAMEPOINTERREL;

typedef struct DEFRANGESYMFRAMEPOINTERREL_FULL_SCOPE { // A frame variable valid in all function scope 
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_DEFRANGE_FRAMEPOINTER_REL

    CV_off32_t      offFramePointer;  // offset to frame pointer
} DEFRANGESYMFRAMEPOINTERREL_FULL_SCOPE;

#define CV_OFFSET_PARENT_LENGTH_LIMIT 12

// Note DEFRANGESYMREGISTERREL and DEFRANGESYMSUBFIELDREGISTER had same layout. 
typedef struct DEFRANGESYMSUBFIELDREGISTER { // A live range of sub field of variable. like locala.i
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_DEFRANGE_SUBFIELD_REGISTER 

    unsigned short     reg;        // Register to hold the value of the symbol
    CV_RANGEATTR       attr;       // Attribute of the register range.
    CV_uoff32_t        offParent : CV_OFFSET_PARENT_LENGTH_LIMIT;  // Offset in parent variable.
    CV_uoff32_t        padding   : 20;  // Padding for future use.
    CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
    CV_LVAR_ADDR_GAP   gaps[CV_ZEROLEN];  // The value is not available in following gaps. 
} DEFRANGESYMSUBFIELDREGISTER;

// Note DEFRANGESYMREGISTERREL and DEFRANGESYMSUBFIELDREGISTER had same layout.
// Used when /GS Copy parameter as local variable or other variable don't cover by FRAMERELATIVE.
typedef struct DEFRANGESYMREGISTERREL {    // A live range of variable related to a register.
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_DEFRANGE_REGISTER_REL

    unsigned short  baseReg;         // Register to hold the base pointer of the symbol
    unsigned short  spilledUdtMember : 1;   // Spilled member for s.i.
    unsigned short  padding          : 3;   // Padding for future use.
    unsigned short  offsetParent     : CV_OFFSET_PARENT_LENGTH_LIMIT;  // Offset in parent variable.
    CV_off32_t      offBasePointer;  // offset to register

    CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
    CV_LVAR_ADDR_GAP   gaps[CV_ZEROLEN];  // The value is not available in following gaps.
} DEFRANGESYMREGISTERREL;

typedef struct DEFRANGESYMHLSL {    // A live range of variable related to a symbol in HLSL code.
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_DEFRANGE_HLSL or S_DEFRANGE_DPC_PTR_TAG

    unsigned short  regType;    // register type from CV_HLSLREG_e

    unsigned short  regIndices       : 2;   // 0, 1 or 2, dimensionality of register space
    unsigned short  spilledUdtMember : 1;   // this is a spilled member
    unsigned short  memorySpace      : 4;   // memory space
    unsigned short  padding          : 9;   // for future use
    
    unsigned short  offsetParent;           // Offset in parent variable.
    unsigned short  sizeInParent;           // Size of enregistered portion

    CV_LVAR_ADDR_RANGE range;               // Range of addresses where this program is valid
    unsigned char   data[CV_ZEROLEN];       // variable length data specifying gaps where the value is not available
                                            // followed by multi-dimensional offset of variable location in register
                                            // space (see CV_DEFRANGESYMHLSL_* macros below)
} DEFRANGESYMHLSL;

#define CV_DEFRANGESYM_GAPS_COUNT(x) \
    (((x)->reclen + sizeof((x)->reclen) - sizeof(DEFRANGESYM)) / sizeof(CV_LVAR_ADDR_GAP))

#define CV_DEFRANGESYMSUBFIELD_GAPS_COUNT(x) \
    (((x)->reclen + sizeof((x)->reclen) - sizeof(DEFRANGESYMSUBFIELD)) / sizeof(CV_LVAR_ADDR_GAP)) 

#define CV_DEFRANGESYMHLSL_GAPS_COUNT(x) \
    (((x)->reclen + sizeof((x)->reclen) - sizeof(DEFRANGESYMHLSL) - (x)->regIndices * sizeof(CV_uoff32_t)) / sizeof(CV_LVAR_ADDR_GAP))

#define CV_DEFRANGESYMHLSL_GAPS_PTR_BASE(x, t)  reinterpret_cast<t>((x)->data)

#define CV_DEFRANGESYMHLSL_GAPS_CONST_PTR(x) \
    CV_DEFRANGESYMHLSL_GAPS_PTR_BASE(x, const CV_LVAR_ADDR_GAP*)

#define CV_DEFRANGESYMHLSL_GAPS_PTR(x) \
    CV_DEFRANGESYMHLSL_GAPS_PTR_BASE(x, CV_LVAR_ADDR_GAP*)

#define CV_DEFRANGESYMHLSL_OFFSET_PTR_BASE(x, t) \
    reinterpret_cast<t>(((CV_LVAR_ADDR_GAP*)(x)->data) + CV_DEFRANGESYMHLSL_GAPS_COUNT(x))
 
#define CV_DEFRANGESYMHLSL_OFFSET_CONST_PTR(x) \
    CV_DEFRANGESYMHLSL_OFFSET_PTR_BASE(x, const CV_uoff32_t*)
 
#define CV_DEFRANGESYMHLSL_OFFSET_PTR(x) \
    CV_DEFRANGESYMHLSL_OFFSET_PTR_BASE(x, CV_uoff32_t*)

#if defined(CC_DP_CXX) && CC_DP_CXX

// Defines a local DPC group shared variable and its location.
typedef struct LOCALDPCGROUPSHAREDSYM {
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_LOCAL_DPC_GROUPSHARED
    CV_typ_t        typind;     // type index   
    CV_LVARFLAGS    flags;      // local var flags

    unsigned short  dataslot;   // Base data (cbuffer, groupshared, etc.) slot
    unsigned short  dataoff;    // Base data byte offset start
    
    unsigned char   name[CV_ZEROLEN];   // Name of this symbol, a null terminated array of UTF8 characters.
} LOCALDPCGROUPSHAREDSYM;

typedef struct DPCSYMTAGMAP {   // A map for DPC pointer tag values to symbol records.
    unsigned short  reclen;     // Record length
    unsigned short  rectyp;     // S_DPC_SYM_TAG_MAP

    CV_DPC_SYM_TAG_MAP_ENTRY mapEntries[CV_ZEROLEN];  // Array of mappings from DPC pointer tag values to symbol record offsets
} DPCSYMTAGMAP;

#define CV_DPCSYMTAGMAP_COUNT(x) \
    (((x)->reclen + sizeof((x)->reclen) - sizeof(DPCSYMTAGMAP)) / sizeof(CV_DPC_SYM_TAG_MAP_ENTRY))

#endif // CC_DP_CXX

typedef enum CV_armswitchtype {
    CV_SWT_INT1         = 0,
    CV_SWT_UINT1        = 1,
    CV_SWT_INT2         = 2,
    CV_SWT_UINT2        = 3,
    CV_SWT_INT4         = 4,
    CV_SWT_UINT4        = 5,
    CV_SWT_POINTER      = 6,
    CV_SWT_UINT1SHL1    = 7,
    CV_SWT_UINT2SHL1    = 8,
    CV_SWT_INT1SHL1     = 9,
    CV_SWT_INT2SHL1     = 10,
    CV_SWT_TBB          = CV_SWT_UINT1SHL1,
    CV_SWT_TBH          = CV_SWT_UINT2SHL1,
} CV_armswitchtype;

typedef struct FUNCTIONLIST {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_CALLERS or S_CALLEES

    unsigned long   count;              // Number of functions
    CV_typ_t        funcs[CV_ZEROLEN];  // List of functions, dim == count
    // unsigned long   invocations[CV_ZEROLEN]; Followed by a parallel array of
    // invocation counts. Counts > reclen are assumed to be zero
} FUNCTIONLIST;

typedef struct POGOINFO {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_POGODATA

    unsigned long   invocations;        // Number of times function was called
    __int64         dynCount;           // Dynamic instruction count
    unsigned long   numInstrs;          // Static instruction count
    unsigned long   staInstLive;        // Final static instruction count (post inlining)
} POGOINFO;

typedef struct ARMSWITCHTABLE {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_ARMSWITCHTABLE

    CV_uoff32_t     offsetBase;         // Section-relative offset to the base for switch offsets
    unsigned short  sectBase;           // Section index of the base for switch offsets
    unsigned short  switchType;         // type of each entry
    CV_uoff32_t     offsetBranch;       // Section-relative offset to the table branch instruction
    CV_uoff32_t     offsetTable;        // Section-relative offset to the start of the table
    unsigned short  sectBranch;         // Section index of the table branch instruction
    unsigned short  sectTable;          // Section index of the table
    unsigned long   cEntries;           // number of switch table entries
} ARMSWITCHTABLE;

typedef struct MODTYPEREF {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_MOD_TYPEREF

    unsigned long   fNone     : 1;      // module doesn't reference any type
    unsigned long   fRefTMPCT : 1;      // reference /Z7 PCH types
    unsigned long   fOwnTMPCT : 1;      // module contains /Z7 PCH types
    unsigned long   fOwnTMR   : 1;      // module contains type info (/Z7)
    unsigned long   fOwnTM    : 1;      // module contains type info (/Zi or /ZI)
    unsigned long   fRefTM    : 1;      // module references type info owned by other module
    unsigned long   reserved  : 9;

    unsigned short  word0;              // these two words contain SN or module index depending
    unsigned short  word1;              // on above flags
} MODTYPEREF;

typedef struct SECTIONSYM {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_SECTION

    unsigned short  isec;               // Section number
    unsigned char   align;              // Alignment of this section (power of 2)
    unsigned char   bReserved;          // Reserved.  Must be zero.
    unsigned long   rva;
    unsigned long   cb;
    unsigned long   characteristics;
    unsigned char   name[1];            // name
} SECTIONSYM;

typedef struct COFFGROUPSYM {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_COFFGROUP

    unsigned long   cb;
    unsigned long   characteristics;
    CV_uoff32_t     off;                // Symbol offset
    unsigned short  seg;                // Symbol segment
    unsigned char   name[1];            // name
} COFFGROUPSYM;

typedef struct EXPORTSYM {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_EXPORT

    unsigned short  ordinal;
    unsigned short  fConstant : 1;      // CONSTANT
    unsigned short  fData : 1;          // DATA
    unsigned short  fPrivate : 1;       // PRIVATE
    unsigned short  fNoName : 1;        // NONAME
    unsigned short  fOrdinal : 1;       // Ordinal was explicitly assigned
    unsigned short  fForwarder : 1;     // This is a forwarder
    unsigned short  reserved : 10;      // Reserved. Must be zero.
    unsigned char   name[1];            // name of
} EXPORTSYM;

//
// Symbol for describing indirect calls when they are using
// a function pointer cast on some other type or temporary.
// Typical content will be an LF_POINTER to an LF_PROCEDURE
// type record that should mimic an actual variable with the
// function pointer type in question.
//
// Since the compiler can sometimes tail-merge a function call
// through a function pointer, there may be more than one
// S_CALLSITEINFO record at an address.  This is similar to what
// you could do in your own code by:
//
//  if (expr)
//      pfn = &function1;
//  else
//      pfn = &function2;
//
//  (*pfn)(arg list);
//

typedef struct CALLSITEINFO {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_CALLSITEINFO
    CV_off32_t      off;                // offset of call site
    unsigned short  sect;               // section index of call site
    unsigned short  __reserved_0;       // alignment padding field, must be zero
    CV_typ_t        typind;             // type index describing function signature
} CALLSITEINFO;

typedef struct HEAPALLOCSITE {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_HEAPALLOCSITE
    CV_off32_t      off;                // offset of call site
    unsigned short  sect;               // section index of call site
    unsigned short  cbInstr;            // length of heap allocation call instruction
    CV_typ_t        typind;             // type index describing function signature
} HEAPALLOCSITE;

// Frame cookie information

typedef enum CV_cookietype_e
{
   CV_COOKIETYPE_COPY = 0, 
   CV_COOKIETYPE_XOR_SP, 
   CV_COOKIETYPE_XOR_BP,
   CV_COOKIETYPE_XOR_R13,
} CV_cookietype_e;

// Symbol for describing security cookie's position and type 
// (raw, xor'd with esp, xor'd with ebp).

typedef struct FRAMECOOKIE {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_FRAMECOOKIE
    CV_off32_t      off;                // Frame relative offset
    unsigned short  reg;                // Register index
    CV_cookietype_e cookietype;         // Type of the cookie
    unsigned char   flags;              // Flags describing this cookie
} FRAMECOOKIE;

typedef enum CV_DISCARDED_e
{
   CV_DISCARDED_UNKNOWN,
   CV_DISCARDED_NOT_SELECTED,
   CV_DISCARDED_NOT_REFERENCED,
} CV_DISCARDED_e;

typedef struct DISCARDEDSYM {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_DISCARDED
    unsigned long   discarded : 8;      // CV_DISCARDED_e
    unsigned long   reserved : 24;      // Unused
    unsigned long   fileid;             // First FILEID if line number info present
    unsigned long   linenum;            // First line number
    char            data[CV_ZEROLEN];   // Original record(s) with invalid type indices
} DISCARDEDSYM;

typedef struct REFMINIPDB {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_REF_MINIPDB
    union {
        unsigned long  isectCoff;       // coff section
        CV_typ_t       typind;          // type index
    };
    unsigned short  imod;               // mod index
    unsigned short  fLocal   :  1;      // reference to local (vs. global) func or data
    unsigned short  fData    :  1;      // reference to data (vs. func)
    unsigned short  fUDT     :  1;      // reference to UDT
    unsigned short  fLabel   :  1;      // reference to label
    unsigned short  fConst   :  1;      // reference to const
    unsigned short  reserved : 11;      // reserved, must be zero
    unsigned char   name[1];            // zero terminated name string
} REFMINIPDB;

typedef struct PDBMAP {
    unsigned short  reclen;             // Record length
    unsigned short  rectyp;             // S_PDBMAP
    unsigned char   name[CV_ZEROLEN];   // zero terminated source PDB filename followed by zero
                                        // terminated destination PDB filename, both in wchar_t
} PDBMAP;

//
// V7 line number data types
//

enum DEBUG_S_SUBSECTION_TYPE {
    DEBUG_S_IGNORE = 0x80000000,    // if this bit is set in a subsection type then ignore the subsection contents

    DEBUG_S_SYMBOLS = 0xf1,
    DEBUG_S_LINES,
    DEBUG_S_STRINGTABLE,
    DEBUG_S_FILECHKSMS,
    DEBUG_S_FRAMEDATA,
    DEBUG_S_INLINEELINES,
    DEBUG_S_CROSSSCOPEIMPORTS,
    DEBUG_S_CROSSSCOPEEXPORTS,

    DEBUG_S_IL_LINES,
    DEBUG_S_FUNC_MDTOKEN_MAP,
    DEBUG_S_TYPE_MDTOKEN_MAP,
    DEBUG_S_MERGED_ASSEMBLYINPUT,

    DEBUG_S_COFF_SYMBOL_RVA,
};

struct CV_DebugSSubsectionHeader_t {
    enum DEBUG_S_SUBSECTION_TYPE type; 
    CV_off32_t                   cbLen;
};

struct CV_DebugSLinesHeader_t {
    CV_off32_t     offCon;
    unsigned short segCon;
    unsigned short flags;
    CV_off32_t     cbCon;
};

struct CV_DebugSLinesFileBlockHeader_t {
    CV_off32_t     offFile;
    CV_off32_t     nLines;
    CV_off32_t     cbBlock;
    // CV_Line_t      lines[nLines];
    // CV_Column_t    columns[nColumns];
};

//
// Line flags (data present)
//
#define CV_LINES_HAVE_COLUMNS 0x0001

struct CV_Line_t {
        unsigned long   offset;             // Offset to start of code bytes for line number
        unsigned long   linenumStart:24;    // line where statement/expression starts
        unsigned long   deltaLineEnd:7;     // delta to line where statement ends (optional)
        unsigned long   fStatement:1;       // true if a statement linenumber, else an expression line num
};

typedef unsigned short CV_columnpos_t;    // byte offset in a source line

struct CV_Column_t {
    CV_columnpos_t offColumnStart;
    CV_columnpos_t offColumnEnd;
};

struct tagFRAMEDATA {
    unsigned long   ulRvaStart;
    unsigned long   cbBlock;
    unsigned long   cbLocals;
    unsigned long   cbParams;
    unsigned long   cbStkMax;
    unsigned long   frameFunc;
    unsigned short  cbProlog;
    unsigned short  cbSavedRegs;
    unsigned long   fHasSEH:1;
    unsigned long   fHasEH:1;
    unsigned long   fIsFunctionStart:1;
    unsigned long   reserved:29;
};

typedef struct tagFRAMEDATA FRAMEDATA, * PFRAMEDATA;

typedef struct tagXFIXUP_DATA {
   unsigned short wType;
   unsigned short wExtra;
   unsigned long rva;
   unsigned long rvaTarget;
} XFIXUP_DATA;

// Those cross scope IDs are private convention, 
// it used to delay the ID merging for frontend and backend even linker. 
// It is transparent for DIA client. 
// Use those ID will let DIA run a litter slower and but 
// avoid the copy type tree in some scenarios.

#ifdef  __cplusplus
namespace CodeViewInfo 
{

typedef struct ComboID
{
    static const unsigned int IndexBitWidth = 20;
    static const unsigned int ImodBitWidth = 12;

    ComboID(unsigned short imod, unsigned int index)
    {
        m_comboID = (((unsigned int) imod) << IndexBitWidth) | index;
    }

    ComboID(unsigned int comboID)
    {
        m_comboID = comboID;
    }

    operator unsigned int()
    {
        return m_comboID;
    }

    unsigned short GetModIndex()
    {
        return (unsigned short) (m_comboID >> IndexBitWidth);
    }

    unsigned int GetIndex()
    {
        return (m_comboID & ((1 << IndexBitWidth) - 1));
    }

private:

    unsigned int m_comboID;
} ComboID;


typedef struct CrossScopeId
{
    static const unsigned int LocalIdBitWidth = 20;
    static const unsigned int IdScopeBitWidth = 11;
    static const unsigned int StartCrossScopeId = 
        (unsigned int) (1 << (LocalIdBitWidth + IdScopeBitWidth));
    static const unsigned int LocalIdMask = (1 << LocalIdBitWidth) - 1;
    static const unsigned int ScopeIdMask = StartCrossScopeId - (1 << LocalIdBitWidth);

    // Compilation unit at most reference 1M constructed type.
    static const unsigned int MaxLocalId = (1 << LocalIdBitWidth) - 1;

    // Compilation unit at most reference to another 2K compilation units.
    static const unsigned int MaxScopeId = (1 << IdScopeBitWidth) - 1;

    CrossScopeId(unsigned short aIdScopeId, unsigned int aLocalId) 
    {  
        crossScopeId = StartCrossScopeId
               | (aIdScopeId << LocalIdBitWidth)
               | aLocalId;
    }

    operator unsigned int() {
        return crossScopeId;
    }

    unsigned int GetLocalId() {
        return crossScopeId & LocalIdMask;
    }

    unsigned int GetIdScopeId() {
        return (crossScopeId & ScopeIdMask) >> LocalIdBitWidth;
    }

    static bool IsCrossScopeId(unsigned int i) 
    {
        return (StartCrossScopeId & i) != 0;
    }

    static CrossScopeId Decode(unsigned int i) 
    {
        CrossScopeId retval;
        retval.crossScopeId = i;
        return retval;
    }

private:

    CrossScopeId() {}

    unsigned int crossScopeId;

} CrossScopeId; 

// Combined encoding of TI or FuncId, In compiler implementation
// Id prefixed by 1 if it is function ID.

typedef struct DecoratedItemId
{
    DecoratedItemId(bool isFuncId, CV_ItemId inputId) {
        if (isFuncId) {
            decoratedItemId = 0x80000000 | inputId;
        } else {
            decoratedItemId = inputId;
        }
    }

    DecoratedItemId(CV_ItemId encodedId) {
        decoratedItemId = encodedId;
    }

    operator unsigned int() {
        return decoratedItemId;
    }

    bool IsFuncId() 
    {
        return (decoratedItemId & 0x80000000) == 0x80000000;
    }

    CV_ItemId GetItemId() 
    {
        return decoratedItemId & 0x7fffffff;
    }

private:

    unsigned int decoratedItemId;

} DecoratedItemId;

// Compilation Unit object file path include library name
// Or compile time PDB full path

typedef struct tagPdbIdScope {
    CV_off32_t  offObjectFilePath; 
} PdbIdScope;

// An array of all imports by import module.
// List all cross reference for a specific ID scope.
// Format of DEBUG_S_CROSSSCOPEIMPORTS subsection is 
typedef struct tagCrossScopeReferences {
    PdbIdScope    externalScope;              // Module of definition Scope.
    unsigned int  countOfCrossReferences;     // Count of following array. 
    CV_ItemId     referenceIds[CV_ZEROLEN];   // CV_ItemId in another compilation unit.
} CrossScopeReferences;

// An array of all exports in this module.
// Format of DEBUG_S_CROSSSCOPEEXPORTS subsection is 
typedef struct tagLocalIdAndGlobalIdPair {
    CV_ItemId localId;    // local id inside the compile time PDB scope. 0 based
    CV_ItemId globalId;   // global id inside the link time PDB scope, if scope are different.
} LocalIdAndGlobalIdPair;

// Format of DEBUG_S_INLINEELINEINFO subsection
// List start source file information for an inlined function.

#define CV_INLINEE_SOURCE_LINE_SIGNATURE     0x0
#define CV_INLINEE_SOURCE_LINE_SIGNATURE_EX  0x1

typedef struct tagInlineeSourceLine {
    CV_ItemId      inlinee;       // function id.
    CV_off32_t     fileId;        // offset into file table DEBUG_S_FILECHKSMS
    CV_off32_t     sourceLineNum; // definition start line number.
} InlineeSourceLine;

typedef struct tagInlineeSourceLineEx {
    CV_ItemId      inlinee;       // function id
    CV_off32_t     fileId;        // offset into file table DEBUG_S_FILECHKSMS
    CV_off32_t     sourceLineNum; // definition start line number
    unsigned int   countOfExtraFiles;
    CV_off32_t     extraFileId[CV_ZEROLEN];
} InlineeSourceLineEx;

// BinaryAnnotations ::= BinaryAnnotationInstruction+
// BinaryAnnotationInstruction ::= BinaryAnnotationOpcode Operand+
//
// The binary annotation mechanism supports recording a list of annotations
// in an instruction stream.  The X64 unwind code and the DWARF standard have
// similar design.
//
// One annotation contains opcode and a number of 32bits operands.
//
// The initial set of annotation instructions are for line number table
// encoding only.  These annotations append to S_INLINESITE record, and
// operands are unsigned except for BA_OP_ChangeLineOffset.

enum BinaryAnnotationOpcode
{
    BA_OP_Invalid,               // link time pdb contains PADDINGs
    BA_OP_CodeOffset,            // param : start offset 
    BA_OP_ChangeCodeOffsetBase,  // param : nth separated code chunk (main code chunk == 0)
    BA_OP_ChangeCodeOffset,      // param : delta of offset
    BA_OP_ChangeCodeLength,      // param : length of code, default next start
    BA_OP_ChangeFile,            // param : fileId 
    BA_OP_ChangeLineOffset,      // param : line offset (signed)
    BA_OP_ChangeLineEndDelta,    // param : how many lines, default 1
    BA_OP_ChangeRangeKind,       // param : either 1 (default, for statement)
                                 //         or 0 (for expression)

    BA_OP_ChangeColumnStart,     // param : start column number, 0 means no column info
    BA_OP_ChangeColumnEndDelta,  // param : end column number delta (signed)

    // Combo opcodes for smaller encoding size.

    BA_OP_ChangeCodeOffsetAndLineOffset,  // param : ((sourceDelta << 4) | CodeDelta)
    BA_OP_ChangeCodeLengthAndCodeOffset,  // param : codeLength, codeOffset

    BA_OP_ChangeColumnEnd,       // param : end column number
};

inline int BinaryAnnotationInstructionOperandCount(BinaryAnnotationOpcode op)
{
    return (op == BA_OP_ChangeCodeLengthAndCodeOffset) ? 2 : 1;
}

///////////////////////////////////////////////////////////////////////////////
//
// This routine a simplified variant from cor.h.
//
// Compress an unsigned integer (iLen) and store the result into pDataOut.
//
// Return value is the number of bytes that the compressed data occupies.  It
// is caller's responsibilityt to ensure *pDataOut has at least 4 bytes to be
// written to.
//
// Note that this function returns -1 if iLen is too big to be compressed.
// We currently can only encode numbers no larger than 0x1FFFFFFF.
//
///////////////////////////////////////////////////////////////////////////////

typedef unsigned __int8 UInt8;
typedef unsigned __int32 UInt32;

typedef UInt8 CompressedAnnotation;
typedef CompressedAnnotation* PCompressedAnnotation;

inline UInt32 CVCompressData(
    UInt32  iLen,       // [IN]  given uncompressed data
    void *  pDataOut)   // [OUT] buffer for the compressed data
{
    UInt8 *pBytes = reinterpret_cast<UInt8 *>(pDataOut);

    if (iLen <= 0x7F) {
        *pBytes = UInt8(iLen);
        return 1;
    }

    if (iLen <= 0x3FFF) {
        *pBytes     = UInt8((iLen >> 8) | 0x80);
        *(pBytes+1) = UInt8(iLen & 0xff);
        return 2;
    }

    if (iLen <= 0x1FFFFFFF) {
        *pBytes     = UInt8((iLen >> 24) | 0xC0);
        *(pBytes+1) = UInt8((iLen >> 16) & 0xff);
        *(pBytes+2) = UInt8((iLen >> 8)  & 0xff);
        *(pBytes+3) = UInt8(iLen & 0xff);
        return 4;
    }

    return (UInt32) -1;
}

///////////////////////////////////////////////////////////////////////////////
//
// Uncompress the data in pData and store the result into pDataOut.
//
// Return value is the uncompressed unsigned integer.  pData is incremented to
// point to the next piece of uncompressed data.
// 
// Returns -1 if what is passed in is incorrectly compressed data, such as
// (*pBytes & 0xE0) == 0xE0.
//
///////////////////////////////////////////////////////////////////////////////

inline UInt32 CVUncompressData(
    PCompressedAnnotation & pData)    // [IN,OUT] compressed data 
{
    UInt32 res = (UInt32)(-1);

    if ((*pData & 0x80) == 0x00) {
        // 0??? ????

        res = (UInt32)(*pData++);
    }
    else if ((*pData & 0xC0) == 0x80) {
        // 10?? ????

        res = (UInt32)((*pData++ & 0x3f) << 8);
        res |= *pData++;
    }
    else if ((*pData & 0xE0) == 0xC0) {
        // 110? ???? 

        res = (*pData++ & 0x1f) << 24;
        res |= *pData++ << 16;
        res |= *pData++ << 8;
        res |= *pData++;
    }

    return res; 
}

// Encode smaller absolute numbers with smaller buffer.
//
// General compression only work for input < 0x1FFFFFFF 
// algorithm will not work on 0x80000000 

inline unsigned __int32 EncodeSignedInt32(__int32 input)
{
    unsigned __int32 rotatedInput;

    if (input >= 0) {
        rotatedInput = input << 1;
    } else {
        rotatedInput = ((-input) << 1) | 1;
    }

    return rotatedInput;
}

inline __int32 DecodeSignedInt32(unsigned __int32 input)
{
    __int32 rotatedInput;

    if (input & 1) {
        rotatedInput = - (int)(input >> 1);
    } else {
        rotatedInput = input >> 1;
    }

    return rotatedInput;
}

}
#endif
#pragma pack ( pop )

#endif /* CV_INFO_INCLUDED */

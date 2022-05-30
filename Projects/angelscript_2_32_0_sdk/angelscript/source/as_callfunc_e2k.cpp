/*
   AngelCode Scripting Library
   Copyright (c) 2003-2022 Andreas Jonsson

   This software is provided 'as-is', without any express or implied
   warranty. In no event will the authors be held liable for any
   damages arising from the use of this software.

   Permission is granted to anyone to use this software for any
   purpose, including commercial applications, and to alter it and
   redistribute it freely, subject to the following restrictions:

   1. The origin of this software must not be misrepresented; you
      must not claim that you wrote the original software. If you use
      this software in a product, an acknowledgment in the product
      documentation would be appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and
      must not be misrepresented as being the original software.

   3. This notice may not be removed or altered from any source
      distribution.

   The original version of this library can be located at:
   http://www.angelcode.com/angelscript/

   Andreas Jonsson
   andreas@angelcode.com
*/

#include <stdio.h>
#include <stdlib.h>

#include "as_config.h"

#ifndef AS_MAX_PORTABILITY
#ifdef AS_E2K

#include "as_callfunc.h"
#include "as_scriptengine.h"
#include "as_texts.h"
#include "as_context.h"

BEGIN_AS_NAMESPACE

extern "C" asQWORD CallE2K(const asQWORD *args, asQWORD *res, int paramSize, asQWORD func, asQWORD & retQW2)
{
        asQWORD res1, res2;

        __asm__ __volatile__
        (
        /* prepare the inputs */
        "{\n\t"
        "   addd,0 %[args], 0x0, %%dr0\n\t"
        "   addd,1 %[func], 0x0, %%dr1\n\t"
        "   addd,2 %[paramSize], 0x0, %%dr2\n\t"
        "   addd,3 %[res], 0x0, %%dr3\n\t"
        "}\n\t"
        /* first 8 arguments are passed via registers (db[0] - db[7]) */
        "{\n\t"
        "  ldd,2  [%%dr0 + 0x00], %%db[0]\n\t"
        "  ldd,5  [%%dr0 + 0x08], %%db[1]\n\t"
        "}\n\t"
        "{\n\t"
        "  ldd,2  [%%dr0 + 0x10], %%db[2]\n\t"
        "  ldd,5  [%%dr0 + 0x18], %%db[3]\n\t"
        "}\n\t"
        "{\n\t"
        "  ldd,2  [%%dr0 + 0x20], %%db[4]\n\t"
        "  ldd,5  [%%dr0 + 0x28], %%db[5]\n\t"
        "}\n\t"
        "{\n\t"
        "  ldd,2  [%%dr0 + 0x30], %%db[6]\n\t"
        "  ldd,5  [%%dr0 + 0x38], %%db[7]\n\t"
        "}\n\t"
        /* do we need to pass arguments via stack - dr2 <= 0x40? (=8 arguments 8 bytes each) */
        "{\n\t"
        "  disp %%ctpr1, .L1\n\t"
        "  cmpbedb %%dr2, 0x40, %%pred0\n\t"
        "}\n\t"
        "{\n\t"
        "  ct %%ctpr1 ? %%pred0\n\t"
        "}\n\t"
        /* rest of the arguments are passed via stack (stack pointer is dr4) */
        "{\n\t"
        "  addd,0 0x0, 0x0, %%dr5\n\t"
        "}\n\t"
        /* stack offset = -number of arguments * 8 */
        "{\n\t"
        "  subd,1  %%dr5, %%dr2, %%dr5\n\t"
        "}\n\t"
        "{\n\t"
        "  getsp,0   %%dr5, %%dr4\n\t"
        "}\n\t"
        /* current offset (dr5), starting from 0x40 (after first 8 arguments 8 bytes each) */
        "{\n\t"
        "  addd,0  0x0, 0x40, %%dr5\n\t"
        "}\n\t"
        ".L2:\n\t"
        /* load an argument from the args array (dr6 = dr0[dr5])
        "{\n\t"
        "  ldd,2  %%dr0, %%dr5, %%dr6\n\t"
        "}\n\t"
         /* store an argument into the stack (dr4[dr5] = dr6)
        "{\n\t"
        "  std,2  %%dr4, %%dr5, %%dr6\n\t"
        "}\n\t"
        /* increase offset to the next arg, dr5 += 8 */
        "{\n\t"
        "  addd,0  %%dr5, 0x08, %%dr5\n\t"
        "}\n\t"
        /* offset(dr5) == paramSize(dr2)? -> pred0 */
        "{\n\t"
        "  disp %%ctpr1, .L2\n\t"
        "  cmpedb %%dr5, %%dr2, %%pred0\n\t"
        "}\n\t"
        "{\n\t"
        "  ct %%ctpr1 ? ~%%pred0\n\t"
        "}\n\t"
        ".L1:\n\t"
        /* actuallly call the function */
        "{\n\t"
        "  movtd %%dr1, %%ctpr1\n\t"
        "}\n\t"
        "{\n\t"
        "  call %%ctpr1, wbs = %#\n\t"
        "}\n\t"
        /* store the result */
        "{\n\t"
        "  std,2  %%dr3, 0x00, %%db[0]\n\t"
        "  std,5  %%dr3, 0x08, %%db[1]\n\t"
        "}\n\t"
        "{\n\t"
        "  std,2  %%dr3, 0x10, %%db[2]\n\t"
        "  std,5  %%dr3, 0x18, %%db[3]\n\t"
        "}\n\t"
        "{\n\t"
        "  std,2  %%dr3, 0x20, %%db[4]\n\t"
        "  std,5  %%dr3, 0x28, %%db[5]\n\t"
        "}\n\t"
        "{\n\t"
        "  std,2  %%dr3, 0x30, %%db[6]\n\t"
        "  std,5  %%dr3, 0x38, %%db[7]\n\t"
        "}\n\t"
        "{\n\t"
        "  addd,0  0x0, %%db[0], %[res1]\n\t"
        "  addd,1  0x0, %%db[1], %[res2]\n\t"
        "}\n\t"
        :
          [res1] "=r" (res1)
          [res2] "=r" (res2)
        :
          [args] "ri" (args)
          [func] "ri" (func)
          [paramSize] "ri" (paramSize)
          [res] "ri" (res)

        : "ctpr1", "b[0]", "b[1]", "b[2]", "b[3]", "b[4]", "b[5]", "b[6]", "b[7]", "pred0", "r4", "r5"
        );

        retQW2 = res2;
        return res1;
}

asQWORD CallSystemFunctionNative(asCContext *context, asCScriptFunction *descr, void *obj, asDWORD *args, void *retPointer, asQWORD & retQW2, void *secondObject)
{
        asCScriptEngine *engine = context->m_engine;
        asSSystemFunctionInterface *sysFunc = descr->sysFuncIntf;

        asQWORD  retQW             = 0;
        asFUNCTION_t func              = sysFunc->func;
        asUINT   paramSize         = 0; // QWords
        asFUNCTION_t   *vftable;

        asQWORD  allArgBuffer[64] = {0};
        asQWORD  allResBuffer[64] = {0};

        int callConv = sysFunc->callConv;

        bool isComplex = (descr->returnType.GetTypeInfo() != 0) &&
                (0 != (descr->returnType.GetTypeInfo()->flags & COMPLEX_RETURN_MASK)) &&
                !descr->returnType.IsObjectHandle() &&
                !descr->returnType.IsReference();

        if( sysFunc->hostReturnInMemory && isComplex)
        {
                // The return is made in memory
                callConv++;

                // Set the return pointer as the first argument
                allArgBuffer[paramSize++] = (asQWORD)retPointer;
        }

        // Optimization to avoid check 12 values (all ICC_ that contains THISCALL)
        if( (callConv >= ICC_THISCALL && callConv <= ICC_VIRTUAL_THISCALL_RETURNINMEM) ||
                (callConv >= ICC_THISCALL_OBJLAST && callConv <= ICC_VIRTUAL_THISCALL_OBJFIRST_RETURNINMEM) )
        {
                // Add the object pointer as the first parameter
                allArgBuffer[paramSize++] = (asQWORD)obj;
        }

        if( callConv == ICC_CDECL_OBJFIRST ||
                callConv == ICC_CDECL_OBJFIRST_RETURNINMEM )
        {
                // Add the object pointer as the first parameter
                allArgBuffer[paramSize++] = (asQWORD)obj;
        }
        else if( callConv == ICC_THISCALL_OBJFIRST ||
                callConv == ICC_THISCALL_OBJFIRST_RETURNINMEM ||
                callConv == ICC_VIRTUAL_THISCALL_OBJFIRST ||
                callConv == ICC_VIRTUAL_THISCALL_OBJFIRST_RETURNINMEM )
        {
                // Add the object pointer as the first parameter
                allArgBuffer[paramSize++] = (asQWORD)secondObject;
        }

        if( callConv == ICC_VIRTUAL_THISCALL ||
                callConv == ICC_VIRTUAL_THISCALL_RETURNINMEM ||
                callConv == ICC_VIRTUAL_THISCALL_OBJFIRST ||
                callConv == ICC_VIRTUAL_THISCALL_OBJFIRST_RETURNINMEM ||
                callConv == ICC_VIRTUAL_THISCALL_OBJLAST ||
                callConv == ICC_VIRTUAL_THISCALL_OBJLAST_RETURNINMEM )
        {
                // Get the true function pointer from the virtual function table
                vftable = *(asFUNCTION_t**)obj;
                func = vftable[FuncPtrToUInt(func)/sizeof(void*)];
        }

        // Move the arguments to the buffer
        asUINT dpos = paramSize;
        asUINT spos = 0;
        for( asUINT n = 0; n < descr->parameterTypes.GetLength(); n++ )
        {
                asCDataType &dt = descr->parameterTypes[n];
                if( dt.IsObject() && !dt.IsObjectHandle() && !dt.IsReference() )
                {
                        if(
                                (dt.GetTypeInfo()->flags & COMPLEX_MASK) )
                        {
                                allArgBuffer[dpos++] = *(asQWORD*)&args[spos];
                                spos += AS_PTR_SIZE;
                                paramSize++;
                        }
                        else
                        {
                                int size = dt.GetSizeInMemoryBytes();
                                /* large objects must start from the even argument position */
                                if (size > 8 && dpos % 2 == 1)
                                    ++dpos;

                                asUINT dwords = dt.GetSizeInMemoryDWords();

                                // Copy the object's memory to the buffer
                                memcpy(&allArgBuffer[dpos], *(void**)(args+spos), dt.GetSizeInMemoryBytes());

                                // Delete the original memory
                                engine->CallFree(*(char**)(args+spos));
                                spos += AS_PTR_SIZE;
                                asUINT qwords = (dwords >> 1) + (dwords & 1);
                                dpos      += qwords;
                                paramSize += qwords;
                        }
                }
                else if( dt.GetTokenType() == ttQuestion )
                {
                        // Copy the reference and the type id
                        allArgBuffer[dpos++] = *(asQWORD*)&args[spos];
                        spos += 2;
                        allArgBuffer[dpos++] = args[spos++];
                        paramSize += 2;
                }
                else
                {
                        // Copy the value directly
                        asUINT dwords = dt.GetSizeOnStackDWords();
                        if( dwords > 1 )
                        {
                                allArgBuffer[dpos] = *(asQWORD*)&args[spos];

                                dpos++;
                                spos += 2;
                        }
                        else
                        {
                                allArgBuffer[dpos] = args[spos];

                                dpos++;
                                spos++;
                        }

                        paramSize++;
                }
        }

        if( callConv == ICC_CDECL_OBJLAST ||
                callConv == ICC_CDECL_OBJLAST_RETURNINMEM )
        {
                // Add the object pointer as the last parameter
                allArgBuffer[paramSize++] = (asQWORD)obj;
        }
        else if( callConv == ICC_THISCALL_OBJLAST ||
                callConv == ICC_THISCALL_OBJLAST_RETURNINMEM ||
                callConv == ICC_VIRTUAL_THISCALL_OBJLAST ||
                callConv == ICC_VIRTUAL_THISCALL_OBJLAST_RETURNINMEM )
        {
                // Add the object pointer as the last parameter
                allArgBuffer[paramSize++] = (asQWORD)secondObject;
        }

        retQW = CallE2K(allArgBuffer, allResBuffer, paramSize*8, (asPWORD)func, retQW2);

        if( sysFunc->hostReturnInMemory && !isComplex )
        {
           memcpy( retPointer, allResBuffer, descr->returnType.GetSizeInMemoryBytes() );
        }


        return retQW;
}

END_AS_NAMESPACE

#endif // AS_E2K
#endif // AS_MAX_PORTABILITY


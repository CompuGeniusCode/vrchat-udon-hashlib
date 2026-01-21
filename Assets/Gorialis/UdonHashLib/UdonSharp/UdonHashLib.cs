// -*- coding: utf-8 -*-
/*
MIT License

Copyright (c) 2021-present Devon (Gorialis) R

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

using UnityEngine;
using UdonSharp;

public class UdonHashLib : UdonSharpBehaviour
{
    private byte[] _utf8Buf;

    private void EnsureUtf8Capacity(int needed)
    {
        if (_utf8Buf == null || _utf8Buf.Length < needed)
        {
            int n = _utf8Buf == null ? 256 : _utf8Buf.Length;
            while (n < needed) n <<= 1;
            _utf8Buf = new byte[n];
        }
    }

    // Encode to UTF8 into a reusable byte buffer. Returns length.
    private int ToUTF8_Into(char[] characters, int len)
    {
        if (characters == null || len <= 0) {
            return 0; }

        // Worst case 4 bytes per char
        EnsureUtf8Capacity(len * 4);

        int writeIndex = 0;
        for (int i = 0; i < len; i++)
        {
            uint character = characters[i];

            if (character < 0x80)
            {
                _utf8Buf[writeIndex++] = (byte)character;
            }
            else if (character < 0x800)
            {
                _utf8Buf[writeIndex++] = (byte)(0b11000000 | ((character >> 6) & 0b11111));
                _utf8Buf[writeIndex++] = (byte)(0b10000000 | (character & 0b111111));
            }
            else if (character < 0x10000)
            {
                _utf8Buf[writeIndex++] = (byte)(0b11100000 | ((character >> 12) & 0b1111));
                _utf8Buf[writeIndex++] = (byte)(0b10000000 | ((character >> 6) & 0b111111));
                _utf8Buf[writeIndex++] = (byte)(0b10000000 | (character & 0b111111));
            }
            else
            {
                _utf8Buf[writeIndex++] = (byte)(0b11110000 | ((character >> 18) & 0b111));
                _utf8Buf[writeIndex++] = (byte)(0b10000000 | ((character >> 12) & 0b111111));
                _utf8Buf[writeIndex++] = (byte)(0b10000000 | ((character >> 6) & 0b111111));
                _utf8Buf[writeIndex++] = (byte)(0b10000000 | (character & 0b111111));
            }
        }

        return writeIndex;
    }

    private int ToUTF8_Into(string text)
    {
        if (string.IsNullOrEmpty(text)) {
            return 0; }
        var chars = text.ToCharArray();
        return ToUTF8_Into(chars, chars.Length);
    }

    private static readonly char[] HEX = "0123456789abcdef".ToCharArray();

    private char[] _hexOut;

    private void EnsureHexCapacity(int neededChars)
    {
        if (_hexOut == null || _hexOut.Length < neededChars)
        {
            int n = _hexOut == null ? 128 : _hexOut.Length;
            while (n < neededChars) n <<= 1;
            _hexOut = new char[n];
        }
    }

    private string HexFromU32BEWords(ulong[] words, int wordCount)
    {
        // each 32-bit word => 8 hex chars
        int outChars = wordCount * 8;
        EnsureHexCapacity(outChars);

        int o = 0;
        for (int i = 0; i < wordCount; i++)
        {
            uint v = (uint)words[i];
            // big-endian formatting like "{0:x8}" on the word value already in big-endian order in the original code
            // The original SHA1/SHA2 code uses working_variables directly (already big-endian per algorithm output).
            _hexOut[o++] = HEX[(v >> 28) & 0xF];
            _hexOut[o++] = HEX[(v >> 24) & 0xF];
            _hexOut[o++] = HEX[(v >> 20) & 0xF];
            _hexOut[o++] = HEX[(v >> 16) & 0xF];
            _hexOut[o++] = HEX[(v >> 12) & 0xF];
            _hexOut[o++] = HEX[(v >> 8) & 0xF];
            _hexOut[o++] = HEX[(v >> 4) & 0xF];
            _hexOut[o++] = HEX[(v >> 0) & 0xF];
        }

        return new string(_hexOut, 0, outChars);
    }

    private readonly ulong[] sha256_init = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    private readonly ulong[] sha256_constants = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    private readonly int[] sha256_sums = { 7, 18, 3, 17, 19, 10 };
    private readonly int[] sha256_sigmas = { 2, 13, 22, 6, 11, 25 };

    private ulong[] _shaWork;     // 8
    private ulong[] _shaState;    // 8
    private ulong[] _shaW;        // 64
    private byte[] _shaInput;     // 64

    private void EnsureSha256Buffers()
    {
        if (_shaWork == null) _shaWork = new ulong[8];
        if (_shaState == null) _shaState = new ulong[8];
        if (_shaW == null || _shaW.Length != 64) _shaW = new ulong[64];
        if (_shaInput == null || _shaInput.Length != 64) _shaInput = new byte[64];
    }

    // Hash bytes already in _utf8Buf[0..len)
    private string SHA256_FromUtf8Buf(int len)
    {
        EnsureSha256Buffers();

        // init state
        for (int i = 0; i < 8; i++) _shaState[i] = sha256_init[i];

        // process 512-bit chunks
        // iterate over message plus padding: easiest is to build chunk buffer each chunk like original, but reuse arrays.
        int totalLen = len;
        int chunkMod = 64;
        int appendedLen = 8;

        for (int chunkIndex = 0; chunkIndex < totalLen + appendedLen + 1; chunkIndex += chunkMod)
        {
            int chunkSize = Mathf.Min(chunkMod, totalLen - chunkIndex);
            int si = 0;

            for (; si < chunkSize; si++) _shaInput[si] = _utf8Buf[chunkIndex + si];

            if (si < chunkMod && chunkSize >= 0) _shaInput[si++] = 0x80;

            for (; si < chunkMod; si++) _shaInput[si] = 0x00;

            if (chunkSize < chunkMod - appendedLen)
            {
                ulong bitSize = (ulong)totalLen * 8ul;
                _shaInput[63] = (byte)((bitSize >> 0) & 0xFFul);
                _shaInput[62] = (byte)((bitSize >> 8) & 0xFFul);
                _shaInput[61] = (byte)((bitSize >> 16) & 0xFFul);
                _shaInput[60] = (byte)((bitSize >> 24) & 0xFFul);
                _shaInput[59] = (byte)((bitSize >> 32) & 0xFFul);
                _shaInput[58] = (byte)((bitSize >> 40) & 0xFFul);
                _shaInput[57] = (byte)((bitSize >> 48) & 0xFFul);
                _shaInput[56] = (byte)((bitSize >> 56) & 0xFFul);
            }

            // w[0..15]
            int wi = 0;
            for (; wi < 16; wi++)
            {
                ulong v = 0;
                v = (v << 8) | _shaInput[(wi * 4) + 0];
                v = (v << 8) | _shaInput[(wi * 4) + 1];
                v = (v << 8) | _shaInput[(wi * 4) + 2];
                v = (v << 8) | _shaInput[(wi * 4) + 3];
                _shaW[wi] = v & 0xFFFFFFFFul;
            }

            for (; wi < 64; wi++)
            {
                ulong s0r = _shaW[wi - 15];
                ulong s1r = _shaW[wi - 2];

                ulong s0 =
                    (((s0r >> sha256_sums[0]) | (s0r << (32 - sha256_sums[0]))) ^
                     ((s0r >> sha256_sums[1]) | (s0r << (32 - sha256_sums[1]))) ^
                     (s0r >> sha256_sums[2])) & 0xFFFFFFFFul;

                ulong s1 =
                    (((s1r >> sha256_sums[3]) | (s1r << (32 - sha256_sums[3]))) ^
                     ((s1r >> sha256_sums[4]) | (s1r << (32 - sha256_sums[4]))) ^
                     (s1r >> sha256_sums[5])) & 0xFFFFFFFFul;

                _shaW[wi] = (_shaW[wi - 16] + s0 + _shaW[wi - 7] + s1) & 0xFFFFFFFFul;
            }

            // work = state
            for (int i = 0; i < 8; i++) _shaWork[i] = _shaState[i];

            // compress
            for (int i = 0; i < 64; i++)
            {
                ulong e = _shaWork[4];
                ulong a = _shaWork[0];

                ulong ep1 =
                    ((e >> sha256_sigmas[3]) | (e << (32 - sha256_sigmas[3]))) ^
                    ((e >> sha256_sigmas[4]) | (e << (32 - sha256_sigmas[4]))) ^
                    ((e >> sha256_sigmas[5]) | (e << (32 - sha256_sigmas[5])));

                ulong ch = (e & _shaWork[5]) ^ ((0xFFFFFFFFul ^ e) & _shaWork[6]);

                ulong ep0 =
                    ((a >> sha256_sigmas[0]) | (a << (32 - sha256_sigmas[0]))) ^
                    ((a >> sha256_sigmas[1]) | (a << (32 - sha256_sigmas[1]))) ^
                    ((a >> sha256_sigmas[2]) | (a << (32 - sha256_sigmas[2])));

                ulong maj = (a & _shaWork[1]) ^ (a & _shaWork[2]) ^ (_shaWork[1] & _shaWork[2]);

                ulong temp1 = (_shaWork[7] + ep1 + ch + sha256_constants[i] + _shaW[i]) & 0xFFFFFFFFul;
                ulong temp2 = (ep0 + maj) & 0xFFFFFFFFul;

                _shaWork[7] = _shaWork[6];
                _shaWork[6] = _shaWork[5];
                _shaWork[5] = _shaWork[4];
                _shaWork[4] = (_shaWork[3] + temp1) & 0xFFFFFFFFul;
                _shaWork[3] = _shaWork[2];
                _shaWork[2] = _shaWork[1];
                _shaWork[1] = _shaWork[0];
                _shaWork[0] = (temp1 + temp2) & 0xFFFFFFFFul;
            }

            for (int i = 0; i < 8; i++) _shaState[i] = (_shaState[i] + _shaWork[i]) & 0xFFFFFFFFul;
        }

        return HexFromU32BEWords(_shaState, 8);
    }

    public string SHA256_UTF8(string text)
    {
        int len = ToUTF8_Into(text);
        return SHA256_FromUtf8Buf(len);
    }

    // New: hash UTF8 encoded from a char buffer without allocating a string.
    public string SHA256_UTF8_Chars(char[] chars, int len)
    {
        int bLen = ToUTF8_Into(chars, len);
        return SHA256_FromUtf8Buf(bLen);
    }
}

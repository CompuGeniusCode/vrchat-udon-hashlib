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

using UdonSharp;

public class UdonHashLib : UdonSharpBehaviour
{
    private readonly char[] HEX = "0123456789abcdef".ToCharArray();

    private readonly uint[] sha256_init_u =
    {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };

    private readonly uint[] sha256_constants_u =
    {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };

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

    private void HexFromU32BEWordsInto(uint[] state8, char[] out64)
    {
        int o = 0;
        for (int i = 0; i < 8; i++)
        {
            uint v = state8[i];
            out64[o++] = HEX[(v >> 28) & 0xFu];
            out64[o++] = HEX[(v >> 24) & 0xFu];
            out64[o++] = HEX[(v >> 20) & 0xFu];
            out64[o++] = HEX[(v >> 16) & 0xFu];
            out64[o++] = HEX[(v >> 12) & 0xFu];
            out64[o++] = HEX[(v >> 8) & 0xFu];
            out64[o++] = HEX[(v >> 4) & 0xFu];
            out64[o++] = HEX[(v >> 0) & 0xFu];
        }
    }

    private uint[] _incState;     // 8
    private uint[] _incW;         // 64
    private byte[] _incBlock;     // 64
    private int _incBlockLen;
    private ulong _incTotalBytes;

    private char[] _incChars;
    private int _incCharsLen;
    private int _incCharIndex;

    private bool _incActive;
    private bool _incFinalized;

    private char[] _incHex64;
    public string SHA256_UTF8_Chars_ResultHex { get; private set; }

    private void EnsureIncBuffers()
    {
        if (_incState == null || _incState.Length != 8) _incState = new uint[8];
        if (_incW == null || _incW.Length != 64) _incW = new uint[64];
        if (_incBlock == null || _incBlock.Length != 64) _incBlock = new byte[64];
        if (_incHex64 == null || _incHex64.Length != 64) _incHex64 = new char[64];
    }

    public void PrewarmSha256Utf8Chars()
    {
        EnsureIncBuffers();
        EnsureHexCapacity(64);
    }

    public void SHA256_UTF8_Chars_Begin(char[] chars, int len)
    {
        EnsureIncBuffers();

        _incChars = chars;
        _incCharsLen = len < 0 ? 0 : len;
        _incCharIndex = 0;

        _incBlockLen = 0;
        _incTotalBytes = 0;

        for (int i = 0; i < 8; i++) _incState[i] = sha256_init_u[i];

        _incActive = true;
        _incFinalized = false;

        SHA256_UTF8_Chars_ResultHex = null;
    }

    public bool SHA256_UTF8_Chars_Step(int charBudget)
    {
        if (!_incActive) return true;
        if (_incFinalized) return true;

        if (_incChars == null || _incCharsLen <= 0)
        {
            FinalizeInc();
            return true;
        }

        int remaining = _incCharsLen - _incCharIndex;
        if (remaining <= 0)
        {
            FinalizeInc();
            return true;
        }

        if (charBudget <= 0) charBudget = 1;
        int n = remaining < charBudget ? remaining : charBudget;

        int end = _incCharIndex + n;
        for (; _incCharIndex < end; _incCharIndex++)
        {
            uint ch = _incChars[_incCharIndex];

            if (ch < 0x80u)
            {
                IncWriteByte((byte)ch);
            }
            else if (ch < 0x800u)
            {
                IncWriteByte((byte)(0xC0u | ((ch >> 6) & 0x1Fu)));
                IncWriteByte((byte)(0x80u | (ch & 0x3Fu)));
            }
            else if (ch < 0x10000u)
            {
                IncWriteByte((byte)(0xE0u | ((ch >> 12) & 0x0Fu)));
                IncWriteByte((byte)(0x80u | ((ch >> 6) & 0x3Fu)));
                IncWriteByte((byte)(0x80u | (ch & 0x3Fu)));
            }
            else
            {
                IncWriteByte((byte)(0xF0u | ((ch >> 18) & 0x07u)));
                IncWriteByte((byte)(0x80u | ((ch >> 12) & 0x3Fu)));
                IncWriteByte((byte)(0x80u | ((ch >> 6) & 0x3Fu)));
                IncWriteByte((byte)(0x80u | (ch & 0x3Fu)));
            }
        }

        if (_incCharIndex >= _incCharsLen)
        {
            FinalizeInc();
            return true;
        }

        return false;
    }

    private void IncWriteByte(byte b)
    {
        _incBlock[_incBlockLen++] = b;
        _incTotalBytes++;

        if (_incBlockLen == 64)
        {
            CompressBlock(_incBlock, _incState, _incW);
            _incBlockLen = 0;
        }
    }

    private static uint ROTR(uint x, int n) => (x >> n) | (x << (32 - n));
    private static uint Ch(uint x, uint y, uint z) => (x & y) ^ (~x & z);
    private static uint Maj(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);
    private static uint Sig0(uint x) => ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    private static uint Sig1(uint x) => ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    private static uint Sum0(uint x) => ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
    private static uint Sum1(uint x) => ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);

    private void CompressBlock(byte[] block64, uint[] state8, uint[] w64)
    {
        for (int i = 0; i < 16; i++)
        {
            int bi = i * 4;
            w64[i] =
                ((uint)block64[bi + 0] << 24) |
                ((uint)block64[bi + 1] << 16) |
                ((uint)block64[bi + 2] << 8) |
                ((uint)block64[bi + 3] << 0);
        }

        for (int i = 16; i < 64; i++)
            w64[i] = w64[i - 16] + Sum0(w64[i - 15]) + w64[i - 7] + Sum1(w64[i - 2]);

        uint a = state8[0];
        uint b = state8[1];
        uint c = state8[2];
        uint d = state8[3];
        uint e = state8[4];
        uint f = state8[5];
        uint g = state8[6];
        uint h = state8[7];

        for (int i = 0; i < 64; i++)
        {
            uint t1 = h + Sig1(e) + Ch(e, f, g) + sha256_constants_u[i] + w64[i];
            uint t2 = Sig0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state8[0] = state8[0] + a;
        state8[1] = state8[1] + b;
        state8[2] = state8[2] + c;
        state8[3] = state8[3] + d;
        state8[4] = state8[4] + e;
        state8[5] = state8[5] + f;
        state8[6] = state8[6] + g;
        state8[7] = state8[7] + h;
    }

    private void FinalizeInc()
    {
        if (_incFinalized) return;

        ulong bitLen = _incTotalBytes * 8ul;

        IncWriteByte(0x80);

        if (_incBlockLen > 56)
        {
            while (_incBlockLen != 0) IncWriteByte(0x00);
        }

        while (_incBlockLen < 56) IncWriteByte(0x00);

        _incBlock[56] = (byte)((bitLen >> 56) & 0xFFul);
        _incBlock[57] = (byte)((bitLen >> 48) & 0xFFul);
        _incBlock[58] = (byte)((bitLen >> 40) & 0xFFul);
        _incBlock[59] = (byte)((bitLen >> 32) & 0xFFul);
        _incBlock[60] = (byte)((bitLen >> 24) & 0xFFul);
        _incBlock[61] = (byte)((bitLen >> 16) & 0xFFul);
        _incBlock[62] = (byte)((bitLen >> 8) & 0xFFul);
        _incBlock[63] = (byte)((bitLen >> 0) & 0xFFul);

        CompressBlock(_incBlock, _incState, _incW);
        _incBlockLen = 0;

        HexFromU32BEWordsInto(_incState, _incHex64);
        EnsureHexCapacity(64);
        for (int i = 0; i < 64; i++) _hexOut[i] = _incHex64[i];
        SHA256_UTF8_Chars_ResultHex = new string(_hexOut, 0, 64);

        _incFinalized = true;
        _incActive = false;
    }

    public string SHA256_UTF8(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            SHA256_UTF8_Chars_Begin(null, 0);
            SHA256_UTF8_Chars_Step(1);
            return SHA256_UTF8_Chars_ResultHex;
        }

        var chars = text.ToCharArray();
        return SHA256_UTF8_Chars(chars, chars.Length);
    }

    public string SHA256_UTF8_Chars(char[] chars, int len)
    {
        SHA256_UTF8_Chars_Begin(chars, len);
        while (!SHA256_UTF8_Chars_Step(8192)) { }
        return SHA256_UTF8_Chars_ResultHex;
    }
}

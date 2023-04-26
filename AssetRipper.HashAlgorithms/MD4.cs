using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;

namespace AssetRipper.HashAlgorithms;
public sealed partial class MD4 : HashAlgorithm
{
	private const int HashSizeInBytes = 16;
	private const int HashSizeInBits = HashSizeInBytes * 8;

	public MD4()
	{
		HashSizeValue = HashSizeInBits;
		Initialize();
	}

	public override void Initialize()
	{
		_a = 0x67452301;
		_b = 0xefcdab89;
		_c = 0x98badcfe;
		_d = 0x10325476;

		_bytesProcessed = 0;
	}

	protected override void HashCore(byte[] array, int offset, int length) => ProcessMessage(new ReadOnlySpan<byte>(array, offset, length));

#if NETSTANDARD
	private
#else
	protected override
#endif
		void HashCore(ReadOnlySpan<byte> source) => ProcessMessage(source);

	protected override byte[] HashFinal()
	{
		ProcessPadding();
		byte[] result = new byte[HashSizeInBytes];
		WriteFinalHashToSpan(result);
		return result;
	}

	private void WriteFinalHashToSpan(Span<byte> span)
	{
		Debug.Assert(span.Length == HashSizeInBytes);
		BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(0 * sizeof(uint), sizeof(uint)), _a);
		BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(1 * sizeof(uint), sizeof(uint)), _b);
		BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(2 * sizeof(uint), sizeof(uint)), _c);
		BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(3 * sizeof(uint), sizeof(uint)), _d);
	}

	private void ProcessPadding()
	{
		int numberOfZeroBytes = CalculateNumberOfZeroBytes(_bytesProcessed);
		Debug.Assert(numberOfZeroBytes >= 0);
		Span<byte> padding = stackalloc byte[1 + sizeof(uint) + sizeof(uint) + numberOfZeroBytes];
		WritePaddingToSpan(padding, numberOfZeroBytes, _bytesProcessed);
		ProcessMessage(padding);
	}

	public byte[] ComputeHash(ReadOnlySpan<byte> source)
	{
		try
		{
			HashCore(source);
			return HashFinal();
		}
		finally
		{
			Initialize();
		}
	}

	public void ComputeHash(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		try
		{
			HashCore(source);
			ProcessPadding();
			WriteFinalHashToSpan(destination.Slice(0, HashSizeInBytes));
		}
		finally
		{
			Initialize();
		}
	}

	private void ProcessMessage(ReadOnlySpan<byte> bytes)
	{
		foreach (byte b in bytes)
		{
			int c = _bytesProcessed & 63;
			int i = c >> 2;
			int s = (c & 3) << 3;

			_x[i] = _x[i] & ~((uint)byte.MaxValue << s) | (uint)b << s;

			if (c == 63)
			{
				Process16WordBlock();
			}

			_bytesProcessed++;
		}
	}

	private static void WritePaddingToSpan(Span<byte> span, int numberOfZeroBytes, int _bytesProcessed)
	{
		//1 byte: 0x80
		//N bytes: 0x00
		//4 bytes: (uint)_bytesProcessed << 3
		//4 bytes: 0x00

		const int NumberOfStartingBytes = 1;

		Debug.Assert(numberOfZeroBytes == CalculateNumberOfZeroBytes(_bytesProcessed));
		Debug.Assert(span.Length == NumberOfStartingBytes + sizeof(uint) + sizeof(uint) + numberOfZeroBytes);

		span[0] = 128;

		for (int i = NumberOfStartingBytes; i < numberOfZeroBytes + NumberOfStartingBytes; i++)
		{
			span[i] = 0;
		}

		int bytesProcessedOffset = NumberOfStartingBytes + numberOfZeroBytes;
		BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(bytesProcessedOffset), (uint)_bytesProcessed << 3);

		int finalOffset = NumberOfStartingBytes + sizeof(uint) + numberOfZeroBytes;
		BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(finalOffset), 0);
	}

	private static int CalculateNumberOfZeroBytes(int bytesProcessed)
	{
		return (bytesProcessed + 8 & 0x7fffffc0) + 55 - bytesProcessed;
	}

	private void Process16WordBlock()
	{
		uint aa = _a;
		uint bb = _b;
		uint cc = _c;
		uint dd = _d;

		foreach (int k in stackalloc int[] { 0, 4, 8, 12 })
		{
			aa = Round1Operation(aa, bb, cc, dd, _x[k], 3);
			dd = Round1Operation(dd, aa, bb, cc, _x[k + 1], 7);
			cc = Round1Operation(cc, dd, aa, bb, _x[k + 2], 11);
			bb = Round1Operation(bb, cc, dd, aa, _x[k + 3], 19);
		}

		foreach (int k in stackalloc int[] { 0, 1, 2, 3 })
		{
			aa = Round2Operation(aa, bb, cc, dd, _x[k], 3);
			dd = Round2Operation(dd, aa, bb, cc, _x[k + 4], 5);
			cc = Round2Operation(cc, dd, aa, bb, _x[k + 8], 9);
			bb = Round2Operation(bb, cc, dd, aa, _x[k + 12], 13);
		}

		foreach (int k in stackalloc int[] { 0, 2, 1, 3 })
		{
			aa = Round3Operation(aa, bb, cc, dd, _x[k], 3);
			dd = Round3Operation(dd, aa, bb, cc, _x[k + 8], 9);
			cc = Round3Operation(cc, dd, aa, bb, _x[k + 4], 11);
			bb = Round3Operation(bb, cc, dd, aa, _x[k + 12], 15);
		}

		unchecked
		{
			_a += aa;
			_b += bb;
			_c += cc;
			_d += dd;
		}
	}

	private static uint ROL(uint value, int numberOfBits)
	{
		return value << numberOfBits | value >> 32 - numberOfBits;
	}

	private static uint Round1Operation(uint a, uint b, uint c, uint d, uint xk, int s)
	{
		unchecked
		{
			return ROL(a + (b & c | ~b & d) + xk, s);
		}
	}

	private static uint Round2Operation(uint a, uint b, uint c, uint d, uint xk, int s)
	{
		unchecked
		{
			return ROL(a + (b & c | b & d | c & d) + xk + 0x5a827999, s);
		}
	}

	private static uint Round3Operation(uint a, uint b, uint c, uint d, uint xk, int s)
	{
		unchecked
		{
			return ROL(a + (b ^ c ^ d) + xk + 0x6ed9eba1, s);
		}
	}

	public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		SharedInstance.ComputeHash(source, destination);
	}

	public static byte[] HashData(ReadOnlySpan<byte> source)
	{
		return SharedInstance.ComputeHash(source);
	}

	private uint _a;
	private uint _b;
	private uint _c;
	private uint _d;
	private UIntFixedBuffer16 _x;
	private int _bytesProcessed;

	[ThreadStatic]
	private static MD4? _sharedInstance;

	private static MD4 SharedInstance
	{
		get
		{
			_sharedInstance ??= new();
			return _sharedInstance;
		}
	}
}

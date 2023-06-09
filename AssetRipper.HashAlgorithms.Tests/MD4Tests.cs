using System.Text;

namespace AssetRipper.HashAlgorithms.Tests;

public partial class MD4Tests
{
	[Test]
	public void HashSizeIs128()
	{
		Assert.That(new MD4().HashSize, Is.EqualTo(128));
	}

	[Test]
	public void InstancesCanBeReused()
	{
		MD4 md4 = new();
		byte[] hash1 = md4.ComputeHash(Encoding.UTF8.GetBytes("abc"));
		_ = md4.ComputeHash(Encoding.UTF8.GetBytes("abcd"));
		byte[] hash2 = md4.ComputeHash(Encoding.UTF8.GetBytes("abc"));
		Assert.That(hash1, Is.EqualTo(hash2));
	}

	[Test]
	public void DestinationSpanMustBeAtLeast16Bytes()
	{
		Assert.Catch(() =>
		{
			MD4.HashData(Array.Empty<byte>(), Array.Empty<byte>());
		});
	}

	[Test]
	public void DestinationSpanCanBeMoreThan16Bytes()
	{
		Assert.DoesNotThrow(() =>
		{
			MD4.HashData(Array.Empty<byte>(), new byte[17]);
		});
	}

	[Test]
	public void EmptySourceDoesNotAffectTheHash()
	{
		byte[] data = Encoding.UTF8.GetBytes("abc");
		byte[] hashExpected;
		{
			MD4 md4 = new();
			hashExpected = md4.ComputeHash(data);
		}
		byte[] hashActual;
		{
			MD4 md4 = new();
			md4.TransformBlock(data, 0, data.Length, null, default);
			hashActual = md4.ComputeHash(Array.Empty<byte>());
		}
		Assert.That(hashActual, Is.EqualTo(hashExpected));
	}
}
namespace AssetRipper.HashAlgorithms;
public sealed partial class MD4
{
	private unsafe struct UIntFixedBuffer16
	{
		private const int Size = 16;
		private fixed uint _buffer[Size];

		public uint this[int index]
		{
			get
			{
				ThrowIfInvalidIndex(index);
				return _buffer[index];
			}
			set
			{
				ThrowIfInvalidIndex(index);
				_buffer[index] = value;
			}
		}

		private static void ThrowIfInvalidIndex(int index)
		{
			if (index < 0 || index >= Size)
			{
				throw new IndexOutOfRangeException();
			}
		}
	}
}

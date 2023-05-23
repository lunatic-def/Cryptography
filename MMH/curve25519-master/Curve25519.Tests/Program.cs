using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Elliptic.Tests
{
    class Program
    {
		public static byte[] ConvertHexStringToByteArray(string hexString)
		{
			byte[] data = new byte[hexString.Length / 2];
			for (int index = 0; index < data.Length; index++)
			{
				string byteValue = hexString.Substring(index * 2, 2);
				data[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
			}

			return data;
		}
		static void Main(string[] args)
        {
			// what server random key
			//byte[] serverRandomBytes = new byte[32] ;
			//RNGCryptoServiceProvider.Create().GetBytes(severRandomBytes);

			//byte[] serverPrivate = Curve25519.ClampPrivateKey(severRandomBytes);
			//byte[] serverPublic = Curve25519.GetPublicKey(severPrivate);

			//Test
			
			byte[] serverPrivate = ConvertHexStringToByteArray("489E9D12939E79A9A776A9DC62A31C89AD387DA86BF6961F5591ECC124799579");
			byte[] serverPublic = ConvertHexStringToByteArray("7972EBCA0F5BAA7DFB5076B6E01D48E003F9DA35E98F0C243D406FDAE2061940");

			//sever know
			byte[] userPublic = ConvertHexStringToByteArray("2C2745C29076F3D0A6D474B7D69B27154787F7E9AC595C65C841D8A759B1CA4D");

			//Create Rs
			//RNGCryptoServiceProvider.Create().GetBytes(rs);
			//rs = ConvertHexStringToByteArray(rs);
			byte[] rsrandom  = new byte[32];
			rsrandom = ConvertHexStringToByteArray("73591fd9b149f6e6b2cf7a5818ef22cc788c50fc30105609b851a5aa339b1ac0");
			byte[] rs = Curve25519.ClampPrivateKey(rsrandom);
			
			// what sever does with user public key
			byte[] serverShared = Curve25519.GetSharedSecret(serverPrivate, userPublic);

			StringBuilder builder = new StringBuilder();
			//Caculate Rs = rs.severpublickey
			byte[] Rs = Curve25519.GetSharedSecret(serverPublic, rs);
			//Received from user
			byte[] Ru = ConvertHexStringToByteArray("53b10fe8a805a94b41949b5fc9ae31e3a80a9289d4dadc5136e47bfe75b4be3b");
			byte[] SK = Curve25519.GetSharedSecret(serverPrivate, rs);
			SK = Curve25519.GetSharedSecret(SK, Ru);
			// Received from user
			byte[] IDu = ConvertHexStringToByteArray("65737038323636");
			byte[] Hu = ConvertHexStringToByteArray("1A201BC4FB55D1AFF05B94FD51EF5877477007E2BBF28AFA461F9B20F37C4BFA48410E39E91DDDC740F3AEB48D6F2BD25E24F1252F6026A36B2A7C5DE7AC3D07");
			//DIDu = h(IDu|severShared|Hu) with sha512
			byte[] DIDu;
			SHA512 shaM = new SHA512Managed();
			DIDu = shaM.ComputeHash(ConvertHexStringToByteArray("657370383236362af449c6fec3d36da8e336356a2c3862bfe1049189ab61d6d0e5c41e9891fd4f1A201BC4FB55D1AFF05B94FD51EF5877477007E2BBF28AFA461F9B20F37C4BFA48410E39E91DDDC740F3AEB48D6F2BD25E24F1252F6026A36B2A7C5DE7AC3D07"));
			byte[] Muphay = shaM.ComputeHash(ConvertHexStringToByteArray("53b10fe8a805a94b41949b5fc9ae31e3a80a9289d4dadc5136e47bfe75b4be3b1a201bc4fb55d1aff05b94fd51ef5877477007e2bbf28afa461f9b20f37c4bfa48410e39e91dddc740f3aeb48d6f2bd25e24f1252f6026a36b2a7c5de7ac3d07064aab244d8ba35446f207c6f86cf69b7be476cc580b1e100b865297ecdf9fb84307dcf95ae96c952cc7721316525a980eeb7b3b31dd4825d3c5bfee5872075b"));
			byte[] Ms = shaM.ComputeHash(ConvertHexStringToByteArray("b954e2969758b99dace5b2c26414f2883af55dc59dffd068b3570bed48372851b3557c90c4e560b87dff47b640b90f16ba855d28ab227b9dd5c7d60774c030679e193f1a882e1a7c3f74855b9ea00888245ee65dfb27b147bb11506841b5021c"));
			Console.WriteLine();
			Console.Write("Server Private in hex: ");
			builder = new StringBuilder();
			for (int i = 0; i < serverPrivate.Length; i++)
			{
				builder.Append(serverPrivate[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());

			Console.Write("Sever Public in hex: ");
			builder = new StringBuilder();
			for (int i = 0; i < serverPublic.Length; i++)
			{
				builder.Append(serverPublic[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());

			Console.Write("User Public in hex: ");
			builder = new StringBuilder();
			for (int i = 0; i < userPublic.Length; i++)
			{
				builder.Append(userPublic[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());

			Console.Write("Server share in hex: ");
			builder = new StringBuilder();
			for (int i = 0; i < serverShared.Length; i++)
			{
				builder.Append(serverShared[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());

			builder = new StringBuilder();
			Console.Write("rs: ");
			for (int i = 0; i < rs.Length; i++)
			{
				builder.Append(rs[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());

			builder = new StringBuilder();
			Console.Write("Rs: ");
			for (int i = 0; i < Rs.Length; i++)
			{
				builder.Append(Rs[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());

			builder = new StringBuilder();

			Console.Write("Ru: ");
			for (int i = 0; i < Ru.Length; i++)
			{
				builder.Append(Ru[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());

			builder = new StringBuilder();
			Console.Write("SK : ");
			for (int i = 0; i < SK.Length; i++)
			{
				builder.Append(SK[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());

			builder = new StringBuilder();
			Console.Write("IDu : ");
			for (int i = 0; i < IDu.Length; i++)
			{
				builder.Append(IDu[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());

			builder = new StringBuilder();
			Console.Write("Hu : ");
			for (int i = 0; i < Hu.Length; i++)
			{
				builder.Append(Hu[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());
			builder = new StringBuilder();
			Console.Write("DIDu : ");
			for (int i = 0; i < DIDu.Length; i++)
			{
				builder.Append(DIDu[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());
			builder = new StringBuilder();
			Console.Write("Mu' : ");
			for (int i = 0; i < Muphay.Length; i++)
			{
				builder.Append(Muphay[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());
			builder = new StringBuilder();
			Console.Write("Ms : ");
			for (int i = 0; i < Ms.Length; i++)
			{
				builder.Append(Ms[i].ToString("x2"));
			}
			Console.WriteLine(builder.ToString());
		}
	}
}

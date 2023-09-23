using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Chaos.NaCl;
using NBitcoin;
using System.Numerics;


namespace dotnetstandard_bip32
{
    public class BIP32
    {
        readonly string curve = "Bitcoin seed";
        //readonly uint hardenedOffset = 0x80000000;
        private string path = "m"; // Add this line to store the full derivation path
        public int chain_counter = 0; // Add this line to keep track of the steps

        public (byte[] Key, byte[] ChainCode) GetMasterKeyFromSeed(string seed)
        {
            //Console.WriteLine($"C# Seed: {seed}");  // Print the seed
            using (HMACSHA512 hmacSha512 = new HMACSHA512(Encoding.UTF8.GetBytes(curve)))
            {
                var i = hmacSha512.ComputeHash(seed.HexToByteArray());
                //Console.WriteLine($"C# HMAC-SHA512 Hash: {BitConverter.ToString(i).Replace("-", "")}");  // Print the hash in hex
                var il = i.Slice(0, 32);
                var ir = i.Slice(32);
                // print il, ir
                Console.WriteLine($"    + il: {BitConverter.ToString(il).Replace("-", "")}");
                Console.WriteLine($"    + ir: {BitConverter.ToString(ir).Replace("-", "")}");
                return (Key: il, ChainCode: ir);
            }
        }

        private (byte[] Key, byte[] ChainCode) GetChildKeyDerivation(byte[] key, byte[] chainCode, uint index)
        {
            Console.WriteLine($"\n* step {chain_counter} index: {index}");
            chain_counter += 1; // Increment the counter for the next step
            // Update the path variable
            path += "/" + index.ToString();
            if ((index & 0x80000000) != 0)
            {
                path += "<sub>H</sub>";
            }
            
            // Print the full derivation path
            Console.WriteLine($"  * chain path: {path}");
            // ... existing code ...
            //counter += 1; // Increment the counter for the next step

            BigEndianBuffer buffer = new BigEndianBuffer();            
            if (index == 0) 
            {
                buffer.Write(GetPublicKey(key));
            }
            else 
            {
                buffer.Write(new byte[] { 0 });
                buffer.Write(key);
            }
            buffer.WriteUInt(index);
            /*if (index == 0) 
            {
                buffer.Write(new byte[] { 0, 0, 0, 0 });  // Manually write 4 bytes of zero for the index 0
                Console.WriteLine("        > C# buffer zero");
            }
            else buffer.WriteUInt(index);*/

            using (HMACSHA512 hmacSha512 = new HMACSHA512(chainCode))
            {
                Console.WriteLine("      * C# Pre-HMAC variable key: " + BitConverter.ToString(key).Replace("-", ""));
                Console.WriteLine("      * C# Pre-HMAC Buffer: " + BitConverter.ToString(buffer.ToArray()).Replace("-", ""));
                Console.WriteLine("      * C# Pre-HMAC Key: " + BitConverter.ToString(chainCode).Replace("-", ""));
                var i = hmacSha512.ComputeHash(buffer.ToArray());

                var il = i.Slice(0, 32);
                var ir = i.Slice(32);

                // print il, ir
                Console.WriteLine($"    * il: {BitConverter.ToString(il).Replace("-", "")}");
                Console.WriteLine($"    * ir: {BitConverter.ToString(ir).Replace("-", "")}");

                //Reverse the byte array for big-endian interpretation and append a zero byte for positive sign
                BigInteger a = new BigInteger(il.Reverse().Append((byte)0).ToArray());  
                BigInteger parentKeyInt = new BigInteger(key.Reverse().Append((byte)0).ToArray());
                //BigInteger parentKeyInt = new BigInteger(key.Reverse().ToArray()); 

                //Console.WriteLine($"C# GetChildKeyDerivation a: {a}");
                //BigInteger parentKeyInt = new BigInteger(key);  // Convert parent key to BigInteger
                //Console.WriteLine($"C# GetChildKeyDerivation parentKeyInt: {parentKeyInt}");
                //BigInteger curveOrder = ...  // The order of the secp256k1 curve
                BigInteger curveOrder = BigInteger.Parse("115792089237316195423570985008687907852837564279074904382605163141518161494337");

                BigInteger newKey = (a + parentKeyInt) % curveOrder;

                if (a < curveOrder && newKey != 0)
                {
                    //Console.WriteLine("C# GetChildKeyDerivation: The key at this index is valid");
                    //byte[] newKeyBytes = newKey.ToByteArray();  // Convert BigInteger back to byte array
                    byte[] newKeyBytes = newKey.ToByteArray().Reverse().ToArray(); // Convert to big-endian
                    // Make sure newKeyBytes is 32 bytes long
                    if (newKeyBytes.Length < 32)
                    {
                        // Pad with zeros at the beginning (most significant bytes) if less than 32 bytes
                        newKeyBytes = new byte[32 - newKeyBytes.Length].Concat(newKeyBytes).ToArray();
                    }
                    else if (newKeyBytes.Length > 32)
                    {
                        // Truncate most significant bytes if more than 32 bytes
                        newKeyBytes = newKeyBytes.Skip(newKeyBytes.Length - 32).ToArray();
                    }
                    
                    return (Key: newKeyBytes, ChainCode: ir);
                }
                else
                {
                    // The key at this index is invalid, so we increment the index and try again
                    Console.WriteLine("C# GetChildKeyDerivation: The key at this index is invalid, so we increment the index and try again");
                    return GetChildKeyDerivation(key, chainCode, index + 1);
                }

            }
        }

        public byte[] GetPublicKey(byte[] privateKeyBytes, bool withZeroByte = true)
        {
            // Create a new Key object from the private key bytes
            Key privateKey = new Key(privateKeyBytes);

            // Get the public key
            PubKey publicKey = privateKey.PubKey;

            // Serialize to a byte array, in compressed or uncompressed format
            byte[] publicKeyBytes = publicKey.ToBytes();

            return publicKeyBytes;
        }

        public (byte[] Key, byte[] ChainCode) DerivePath(string seed)
        {
            uint index44 = 0x8000002c;
            uint index9000 = 0x80002328;
            uint index0Hardened = 0x80000000;
            uint index0 = 0x00000000;

            Console.WriteLine($"\n* step {chain_counter} index: m");
            chain_counter += 1; // Increment the counter for the next step
            var masterKeyFromSeed = GetMasterKeyFromSeed(seed);
            Console.WriteLine($"  * chain code: {BitConverter.ToString(masterKeyFromSeed.ChainCode).Replace("-", "")}");
            Console.WriteLine($"  * private: {BitConverter.ToString(masterKeyFromSeed.Key).Replace("-", "")}");
            Console.WriteLine($"  * public: {BitConverter.ToString(GetPublicKey(masterKeyFromSeed.Key)).Replace("-", "")}");
            
            var result1 = GetChildKeyDerivation(masterKeyFromSeed.Key, masterKeyFromSeed.ChainCode, index44);
            Console.WriteLine($"  * chain code: {BitConverter.ToString(result1.ChainCode).Replace("-", "")}");
            Console.WriteLine($"  * private: {BitConverter.ToString(result1.Key).Replace("-", "")}");
            Console.WriteLine($"  * public: {BitConverter.ToString(GetPublicKey(result1.Key)).Replace("-", "")}");

            var result2 = GetChildKeyDerivation(result1.Key, result1.ChainCode, index9000);
            Console.WriteLine($"  * chain code: {BitConverter.ToString(result2.ChainCode).Replace("-", "")}");
            Console.WriteLine($"  * private: {BitConverter.ToString(result2.Key).Replace("-", "")}");
            Console.WriteLine($"  * public: {BitConverter.ToString(GetPublicKey(result2.Key)).Replace("-", "")}");

            var result3 = GetChildKeyDerivation(result2.Key, result2.ChainCode, index0Hardened);
            Console.WriteLine($"  * chain code: {BitConverter.ToString(result3.ChainCode).Replace("-", "")}");
            Console.WriteLine($"  * private: {BitConverter.ToString(result3.Key).Replace("-", "")}");
            Console.WriteLine($"  * public: {BitConverter.ToString(GetPublicKey(result3.Key)).Replace("-", "")}");

            var result4 = GetChildKeyDerivation(result3.Key, result3.ChainCode, index0);
            Console.WriteLine($"  * chain code: {BitConverter.ToString(result4.ChainCode).Replace("-", "")}");
            Console.WriteLine($"  * private: {BitConverter.ToString(result4.Key).Replace("-", "")}");
            Console.WriteLine($"  * public: {BitConverter.ToString(GetPublicKey(result4.Key)).Replace("-", "")}");

            var result5 = GetChildKeyDerivation(result4.Key, result4.ChainCode, index0);
            Console.WriteLine($"  * chain code: {BitConverter.ToString(result5.ChainCode).Replace("-", "")}");
            Console.WriteLine($"  * private: {BitConverter.ToString(result5.Key).Replace("-", "")}");
            Console.WriteLine($"  * public: {BitConverter.ToString(GetPublicKey(result5.Key)).Replace("-", "")}");

            return result5;
        }
    }
}
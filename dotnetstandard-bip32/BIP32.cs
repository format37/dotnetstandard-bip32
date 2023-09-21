﻿using System;
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
        readonly uint hardenedOffset = 0x80000000;

        public (byte[] Key, byte[] ChainCode) GetMasterKeyFromSeed(string seed)
        {
            //Console.WriteLine($"C# Seed: {seed}");  // Print the seed
            using (HMACSHA512 hmacSha512 = new HMACSHA512(Encoding.UTF8.GetBytes(curve)))
            {
                var i = hmacSha512.ComputeHash(seed.HexToByteArray());
                //Console.WriteLine($"C# HMAC-SHA512 Hash: {BitConverter.ToString(i).Replace("-", "")}");  // Print the hash in hex
                var il = i.Slice(0, 32);
                var ir = i.Slice(32);
                //Console.WriteLine($"C# Master Key: {BitConverter.ToString(il).Replace("-", "")}");  // Print the master key in hex
                //Console.WriteLine($"C# Chain Code: {BitConverter.ToString(ir).Replace("-", "")}");  // Print the chain code in hex
                return (Key: il, ChainCode: ir);
            }
        }

        private string path = "m"; // Add this line to store the full derivation path
        private int counter = 1; // Add this line to keep track of the steps

        private (byte[] Key, byte[] ChainCode) GetChildKeyDerivation(byte[] key, byte[] chainCode, uint index)
        {

            // Update the path variable
            path += "/" + index.ToString();
            if ((index & 0x80000000) != 0)
            {
                path += "<sub>H</sub>";
            }
            // Print the full derivation path
            Console.WriteLine($">>>C# GetChildKeyDerivation Path: {path} step: {counter}");
            // ... existing code ...
            counter += 1; // Increment the counter for the next step


            //index = 2147483692; // hardcoded "m/44'/9000'/0'/0/0"
            // print chain code
            Console.WriteLine($"C# GetChildKeyDerivation Chain Code: {BitConverter.ToString(chainCode).Replace("-", "")}");
            // print key
            Console.WriteLine($"C# GetChildKeyDerivation Key: {BitConverter.ToString(key).Replace("-", "")}");
            // print index
            Console.WriteLine($"C# GetChildKeyDerivation Index: {index}");            

            BigEndianBuffer buffer = new BigEndianBuffer();

            buffer.Write(new byte[] { 0 });
            buffer.Write(key);
            buffer.WriteUInt(index);

            using (HMACSHA512 hmacSha512 = new HMACSHA512(chainCode))
            {
                var i = hmacSha512.ComputeHash(buffer.ToArray());

                var il = i.Slice(0, 32);
                var ir = i.Slice(32);

                // print il, ir
                Console.WriteLine($"C# GetChildKeyDerivation il: {BitConverter.ToString(il).Replace("-", "")}");
                Console.WriteLine($"C# GetChildKeyDerivation ir: {BitConverter.ToString(ir).Replace("-", "")}");

                // return (Key: il, ChainCode: ir);
                
                // Assuming BigInteger is used for the modular arithmetic
                //BigInteger a = new BigInteger(il);  // Convert byte array il to BigInteger

                // Reverse the byte array for big-endian interpretation
                //BigInteger a = new BigInteger(il.Reverse().ToArray());  
                // Reverse the byte array for big-endian interpretation and append a zero byte for positive sign
                BigInteger a = new BigInteger(il.Reverse().Append((byte)0).ToArray());  
                BigInteger parentKeyInt = new BigInteger(key.Reverse().Append((byte)0).ToArray());
                //BigInteger parentKeyInt = new BigInteger(key.Reverse().ToArray()); 

                Console.WriteLine($"C# GetChildKeyDerivation a: {a}");
                //BigInteger parentKeyInt = new BigInteger(key);  // Convert parent key to BigInteger
                Console.WriteLine($"C# GetChildKeyDerivation parentKeyInt: {parentKeyInt}");
                //BigInteger curveOrder = ...  // The order of the secp256k1 curve
                BigInteger curveOrder = BigInteger.Parse("115792089237316195423570985008687907852837564279074904382605163141518161494337");

                BigInteger newKey = (a + parentKeyInt) % curveOrder;

                if (a < curveOrder && newKey != 0)
                {
                    Console.WriteLine("C# GetChildKeyDerivation: The key at this index is valid");
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

        public byte[] GetPublicKey_v0(byte[] privateKey, bool withZeroByte = true)
        {
            Ed25519.KeyPairFromSeed(out var publicKey, out _, privateKey);

            var zero = new byte[] { 0 };

            var buffer = new BigEndianBuffer();
            if (withZeroByte)
                buffer.Write(zero);

            buffer.Write(publicKey);

            return buffer.ToArray();
        }

        private bool IsValidPath_v0(string path)
        {
            var regex = new Regex("^m(\\/[0-9]+')+$");

            if (!regex.IsMatch(path))
                return false;

            var valid = !(path.Split('/')
                .Slice(1)
                .Select(a => a.Replace("'", ""))
                .Any(a => !Int32.TryParse(a, out _)));

            return valid;
        }

        private bool IsValidPath(string path)
        {
            // Modified regex to allow for optional hardening symbol (')
            var regex = new Regex("^m(\\/[0-9]+')*(\\/[0-9]+)*$");

            if (!regex.IsMatch(path))
                return false;

            var valid = !(path.Split('/')
                .Skip(1) // Skip the "m" part
                .Select(a => a.Replace("'", ""))
                .Any(a => !UInt32.TryParse(a, out _)));

            return valid;
        }

        public (byte[] Key, byte[] ChainCode) DerivePath(string path, string seed)
        {
            var masterKeyFromSeed = GetMasterKeyFromSeed(seed);

            Console.WriteLine($"Master Key: {BitConverter.ToString(masterKeyFromSeed.Key).Replace("-", "")}");
            Console.WriteLine($"Master Chain Code: {BitConverter.ToString(masterKeyFromSeed.ChainCode).Replace("-", "")}");

            uint index44 = 0x8000002c;
            uint index9000 = 0x80002328;
            uint index0Hardened = 0x80000000;
            uint index0 = 0x00000000;

            Console.WriteLine($"C# DerivePath index44: {index44}");
            var result1 = GetChildKeyDerivation(masterKeyFromSeed.Key, masterKeyFromSeed.ChainCode, index44);            
            Console.WriteLine($"\nResult1 Key: {BitConverter.ToString(result1.Key).Replace("-", "")}");
            Console.WriteLine($"Result1 Chain Code: {BitConverter.ToString(result1.ChainCode).Replace("-", "")}");

            Console.WriteLine($"C# DerivePath index9000: {index9000}");
            var result2 = GetChildKeyDerivation(result1.Key, result1.ChainCode, index9000);
            Console.WriteLine($"\nResult2 Key: {BitConverter.ToString(result2.Key).Replace("-", "")}");
            Console.WriteLine($"Result2 Chain Code: {BitConverter.ToString(result2.ChainCode).Replace("-", "")}");

            Console.WriteLine($"C# DerivePath index0Hardened: {index0Hardened}");
            var result3 = GetChildKeyDerivation(result2.Key, result2.ChainCode, index0Hardened);
            Console.WriteLine($"\nResult3 Key: {BitConverter.ToString(result3.Key).Replace("-", "")}");
            Console.WriteLine($"Result3 Chain Code: {BitConverter.ToString(result3.ChainCode).Replace("-", "")}");

            Console.WriteLine($"C# DerivePath index0: {index0}");
            var result4 = GetChildKeyDerivation(result3.Key, result3.ChainCode, index0);
            Console.WriteLine($"\nResult4 Key: {BitConverter.ToString(result4.Key).Replace("-", "")}");
            Console.WriteLine($"Result4 Chain Code: {BitConverter.ToString(result4.ChainCode).Replace("-", "")}");

            Console.WriteLine($"C# DerivePath index0: {index0}");
            var result5 = GetChildKeyDerivation(result4.Key, result4.ChainCode, index0);
            Console.WriteLine($"\nResult5 Key: {BitConverter.ToString(result5.Key).Replace("-", "")}");
            Console.WriteLine($"Result5 Chain Code: {BitConverter.ToString(result5.ChainCode).Replace("-", "")}");

            return result5;
        }

        public (byte[] Key, byte[] ChainCode) DerivePath_v1(string path, string seed)
        {

            var masterKeyFromSeed = GetMasterKeyFromSeed(seed);

            uint index44 = 0x8000002c; // Or 2147483692 in decimal
            uint index9000 = 0x80002328; // Or 2147488816 in decimal
            uint index0Hardened = 0x80000000; // Or 2147483648 in decimal
            uint index0 = 0x00000000; // Or 0 in decimal

            // Derive the keys
            var result1 = GetChildKeyDerivation(masterKeyFromSeed.Key, masterKeyFromSeed.ChainCode, index44);
            var result2 = GetChildKeyDerivation(result1.Key, result1.ChainCode, index9000);
            var result3 = GetChildKeyDerivation(result2.Key, result2.ChainCode, index0Hardened);
            var result4 = GetChildKeyDerivation(result3.Key, result3.ChainCode, index0);
            var result5 = GetChildKeyDerivation(result4.Key, result4.ChainCode, index0);

            return result5;
        }

        public (byte[] Key, byte[] ChainCode) DerivePath_v0(string path, string seed)
        {
            if (!IsValidPath(path))
                throw new FormatException("Invalid derivation path");

            var masterKeyFromSeed = GetMasterKeyFromSeed(seed);

            var segments = path
                .Split('/')
                .Slice(1)
                .Select(a => a.Replace("'", ""))
                .Select(a => Convert.ToUInt32(a, 10));

            var results = segments
                .Aggregate(masterKeyFromSeed, (mks, next) => GetChildKeyDerivation(mks.Key, mks.ChainCode, next + hardenedOffset));


            return results;
        }


    }
}
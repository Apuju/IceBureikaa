﻿using System;
using System.Security.Cryptography;

namespace IceBureikaa.Business.Cryptography
{
    public class HashWrapper
    {
        public byte[] HashMD5(byte[] data)
        {
            byte[] hashText = null;
            try
            {
                using (MD5 hasher = MD5.Create())
                {
                    hashText = hasher.ComputeHash(data);
                }

            }
            catch (Exception)
            {
                throw;
            }
            return hashText;
        }

        public byte[] HashSHA256(byte[] data)
        {
            byte[] hashText = null;
            try
            {
                using (SHA256 hasher = SHA256.Create())
                {
                    hashText = hasher.ComputeHash(data);
                }

            }
            catch (Exception)
            {
                throw;
            }
            return hashText;
        }

        public byte[] HashRFC2898(byte[] data, byte[] salt, int iteration, int hashByteLength)
        {
            byte[] hashText = null;
            try
            {
                using (Rfc2898DeriveBytes hasher = new Rfc2898DeriveBytes(data, salt, iteration))
                {
                    hashText = hasher.GetBytes(hashByteLength);
                }

            }
            catch (Exception)
            {
                throw;
            }
            return hashText;
        }
    }
}

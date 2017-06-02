using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace IceBureikaa.Business.Cryptography
{
    public class RandomWrapper
    {
        public byte[] GenerateData(int byteLength)
        {
            byte[] randomText = null;
            bool go = true;
            if (byteLength <= 0)
            {
                go = false;
            }
            else
            {
                randomText = new byte[byteLength];
            }
            if (go)
            {
                try
                {
                    using (RandomNumberGenerator rngCsp = RandomNumberGenerator.Create())
                    {
                        rngCsp.GetBytes(randomText);
                    }
                }
                catch (Exception)
                {
                    throw;
                }
            }
            return randomText;
        }
    }
}

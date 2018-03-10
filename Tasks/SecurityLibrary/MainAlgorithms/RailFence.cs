using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
             int width = (int)Math.Ceiling( (double)cipherText.Length / key);
             string plainText = "";
             for (int i = 0; i < width; i++)
                  for (int j = i; j < cipherText.Length; j += width)
                       plainText += cipherText[j];
             return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
             string cipherText = "";
             for(int i=0 ; i<key ; i++)
                  for(int j=i ; j<plainText.Length ; j+=key)
                       cipherText += plainText[j];
             return cipherText;
        }
    }
}

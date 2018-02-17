using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
             plainText = plainText.ToLower();
             System.Text.StringBuilder strBuilder = new System.Text.StringBuilder(plainText);
             
             for(int i= 0 ; i<plainText.Length ; i++) 
                  strBuilder[i] = (char)((((int)strBuilder[i] - 97 + key) % 26) + 97);
             
             return strBuilder.ToString();
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
             cipherText = cipherText.ToLower();
             System.Text.StringBuilder strBuilder = new System.Text.StringBuilder(cipherText);

             for (int i = 0; i < cipherText.Length; i++)
                  strBuilder[i] = (char)((((int)strBuilder[i] - 97 - key + 26) % 26) + 97);

             return strBuilder.ToString();
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
             if(plainText.Length != cipherText.Length)
                  throw new Exception();
             plainText = plainText.ToLower();
             cipherText = cipherText.ToLower();
             for(int i = 0; i < 26 ; i++)
                  if (cipherText[0] == (char)((((int)plainText[0] - 97 + i) % 26) + 97))
                       return i;
         
             return -1;
        }
    }
}

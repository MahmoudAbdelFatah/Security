using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
         int key = 0;
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
             cipherText = cipherText.ToLower();
             plainText = plainText.ToLower();
             for (int i = 1; i < cipherText.Length; i++)
             {
                  if (plainText[1] == cipherText[i])
                  {
                       key = i;
                       break;
                  }
             }
             getKey(plainText, cipherText, 0, 1, key);
             return (int)Math.Ceiling((double)(plainText.Length)/ key);
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
        public bool getKey(string plain, string cipher, int i, int j, int key)
        {
             for (int k = (i + 1); k <= cipher.Length; k++)
             {
                  if (k == cipher.Length)
                       k = k % cipher.Length;
                  if(plain[j] == cipher[k])
                  {
                       if (i == 0 && j== 1)
                            key = k;
                       int dif = k > i ? k - i : cipher.Length - (i - k);
                       if (Math.Abs(dif - key) > 1)
                       {
                            if (key < dif)
                                 return false;
                            if (key > dif)
                                 continue;
                       }

                       if (j == plain.Length - 1)
                       {
                            this.key = key;
                            return true;
                       }
                       
                       getKey(plain, cipher, k, j + 1, key);

                  }
                  else if(k == i)
                      break;
             }
             return false;            
        }
    }

}

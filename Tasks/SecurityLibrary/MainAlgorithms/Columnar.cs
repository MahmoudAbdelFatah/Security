using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
         int key = 0;
        public List<int> Analyse(string plainText, string cipherText)
        {
           // throw new NotImplementedException();
             cipherText = cipherText.ToLower();
             plainText = plainText.ToLower();
            
                  getKey(plainText, cipherText, 0, 0, 0);
             int depth = (int)Math.Ceiling((double) plainText.Length / key);

             List<int> keys = Enumerable.Repeat(0, key ).ToList();

             char[,] mat = new char[depth, key];
             for(int i=0 ; i< depth ; i++)
             {
                  for(int j=0 ; j< key ; j++)
                  {
                       //if (i * key + j >= plainText.Length)
                       //     mat[i, j] = 'x';
                       //else
                       if (i * key + j < plainText.Length)
                            mat[i, j] = plainText[i * key + j];
                  }
             }
             int k = 0;
             while (k != cipherText.Length)
             {
                  bool found = false;

                  for (int i = 0; i < key; i++)
                  {
                       for (int j = 0; j < depth; j++)
                       {

                            if (mat[j, i] == '\0' || (k < cipherText.Length && mat[j, i] == cipherText[k]))
                            {
                                 if (mat[j, i] != '\0' && k < cipherText.Length)
                                      k++;
                                 if (j == depth - 1)
                                 {
                                      keys[i] = (k) / depth;
                                      found = true;
                                 }
                            }
                            else if (k < cipherText.Length && mat[j, i] != cipherText[k])
                            {
                                 k = k - j;
                                 break;
                            }
                    
                       }
                       if (found)
                            break;
                  }
             }


             return keys;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string plainText = "";
            int cnt = -1;
            int rows = cipherText.Length / key.Count;
            int cols = key.Count;
            char[,] mat = new char[rows, cols];
            char[,] tmp = new char[rows, cols];

            for (int i = 0; i < cols; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    mat[j, i] = cipherText[++cnt];
                }
            }

            for (int i = 1; i <= cols; i++)
            {
                int col = key.IndexOf(i);
                for (int j = 0; j < rows; j++)
                {
                    tmp[j, col] = mat[j,i-1];
                }
            }

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    plainText += tmp[i, j];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string cipherText = "";
            while(plainText.Length %key.Count !=0)
                plainText +='x';
            int cnt = -1;
            int rows = plainText.Length / key.Count;
            int cols = key.Count;
            char[,] mat = new char[rows, cols];
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    mat[i, j] = plainText[++cnt];
                }
            }
            for (int i = 1; i <= cols; i++)
            {
                int col = key.IndexOf(i);
                for (int j = 0; j < rows; j++)
                {
                    cipherText += mat[j, col];
                }
            }
            return cipherText;
        }
        public bool getKey(string plain, string cipher, int i, int j, int key)
        {

             for (int k = i; k < plain.Length; k++)
             {
                  if (k == plain.Length - 1)
                       this.key = key;
                  if (cipher[j] == plain[k])
                  {
                       int dif = k - i;

                       if (dif == 0 && j != 0)
                            continue;
                       if (j == 1)
                            key = k - i;


                       if (key < dif)
                            return false;
                       if (key > dif)
                            continue;



                       if (getKey(plain, cipher, k, j + 1, key))
                       {

                            return true;

                       }

                  }

             }
             return false;   
                 
               
        }
    }
}

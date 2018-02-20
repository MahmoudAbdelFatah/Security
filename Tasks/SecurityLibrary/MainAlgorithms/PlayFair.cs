using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        
        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();         
             if (cipherText == null || key == null || cipherText.Length == 0 || key.Length == 0)
                  throw new Exception();
             cipherText = cipherText.ToLower();
             key = key.ToLower();
             key = key.Replace("j", "i");
             cipherText = cipherText.Replace("j", "i");

             HashSet<char> alphapets = new HashSet<char> { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
             HashSet<char> setKey = new HashSet<char>();
             char[,] charsMatrix = new char[5, 5];
             foreach (char c in key)
                  setKey.Add(c);
             for (int i = 0; i < 5; i++)
             {
                  for (int j = 0; j < 5; j++)
                  {
                       if (setKey.Count != 0)
                       {
                            charsMatrix[i, j] = setKey.ElementAt(0);
                            alphapets.Remove(setKey.ElementAt(0));
                            setKey.Remove(setKey.ElementAt(0));
                       }
                       else if (alphapets.Count != 0)
                       {
                            charsMatrix[i, j] = alphapets.ElementAt(0);
                            alphapets.Remove(alphapets.ElementAt(0));
                       }
                  }
             }
             
             string plainText = "";
             for (int i = 0; i < cipherText.Length - 1; i += 2)
             {
                  int[] firstCharPos = getIndex(cipherText[i], charsMatrix);
                  int[] secondCharPos = getIndex(cipherText[i + 1], charsMatrix);
                  // 0 for row and 1 for column
                  if (firstCharPos[0] == secondCharPos[0])
                  {
                       plainText = plainText + charsMatrix[firstCharPos[0], (firstCharPos[1] - 1 + 5) % 5];
                       plainText = plainText + charsMatrix[secondCharPos[0], (secondCharPos[1] - 1 + 5) % 5];
                  }
                  else if (firstCharPos[1] == secondCharPos[1])
                  {
                       plainText = plainText + charsMatrix[(firstCharPos[0] - 1 + 5) % 5, firstCharPos[1]];
                       plainText = plainText + charsMatrix[(secondCharPos[0] - 1 + 5) % 5, secondCharPos[1]];
                  }
                  else
                  {
                       plainText = plainText + charsMatrix[firstCharPos[0], secondCharPos[1]];
                       plainText = plainText + charsMatrix[secondCharPos[0], firstCharPos[1]];
                  }
             }
             if (plainText[plainText.Length - 1] == 'x')
                  plainText = plainText.Remove(plainText.Length - 1, 1);

             System.Text.StringBuilder plain = new System.Text.StringBuilder(plainText);

             for (int i = 1; i < plainText.Length - 1; i++)
                  if (plain[i] == 'x' && i%2 != 0 && plain[i - 1] == plain[i + 1])
                            plain[i] = '-';

             plainText = plain.ToString().Replace("-", string.Empty);
             return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
             //throw new NotImplementedException();
             if (plainText == null || key == null || plainText.Length == 0 || key.Length == 0)
                  throw new Exception();
             plainText = plainText.ToLower();
             key = key.ToLower();
             key = key.Replace("j", "i");
             plainText = plainText.Replace("j", "i");

             HashSet<char> alphapets = new HashSet<char> { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
             HashSet<char> setKey = new HashSet<char>();
             char[,] charsMatrix = new char[5, 5];
             foreach (char c in key)
                  setKey.Add(c);
             for (int i = 0; i < 5; i++)
             {
                  for (int j = 0; j < 5; j++)
                  {
                       if (setKey.Count != 0)
                       {
                            charsMatrix[i, j] = setKey.ElementAt(0);
                            alphapets.Remove(setKey.ElementAt(0));
                            setKey.Remove(setKey.ElementAt(0));
                       }
                       else if (alphapets.Count != 0)
                       {
                            charsMatrix[i, j] = alphapets.ElementAt(0);
                            alphapets.Remove(alphapets.ElementAt(0));
                       }
                  }
             }
             plainText = plainText.Replace(" ", string.Empty);

             for (int i = 0; i < plainText.Length -1 ; i+=2)
                  if (plainText[i] == plainText[i + 1])
                       plainText = plainText.Insert(i + 1, "x");
                       
             if (plainText.Length % 2 != 0)
                  plainText = plainText + "x";

             string cipherText = "";
             for (int i = 0; i < plainText.Length - 1; i += 2)
             {
                  int[] firstCharPos = getIndex(plainText[i], charsMatrix);
                  int[] secondCharPos = getIndex(plainText[i + 1], charsMatrix);
                  // 0 for row and 1 for column
                  if (firstCharPos[0] == secondCharPos[0])
                  {
                       cipherText = cipherText + charsMatrix[firstCharPos[0], (firstCharPos[1] + 1) % 5];
                       cipherText = cipherText + charsMatrix[secondCharPos[0], (secondCharPos[1] + 1) % 5];
                  }
                  else if (firstCharPos[1] == secondCharPos[1])
                  {
                       cipherText = cipherText + charsMatrix[(firstCharPos[0] + 1) % 5, firstCharPos[1]];
                       cipherText = cipherText + charsMatrix[(secondCharPos[0] + 1) % 5, secondCharPos[1]];
                  }
                  else
                  {
                       cipherText = cipherText + charsMatrix[firstCharPos[0], secondCharPos[1]];
                       cipherText = cipherText + charsMatrix[secondCharPos[0], firstCharPos[1]];
                  }
             }
             return cipherText;
        }
        public string Analyse(string plainText, string cipherText)
        {
             throw new NotSupportedException();
        }
        public int[] getIndex(char c, char[,] chars)
        {
             for (int i = 0; i < 5; i++)
                  for (int j = 0; j < 5; j++)
                       if (chars[i, j] == c)
                            return new[] { i, j };
             return null;
        }
    }
}

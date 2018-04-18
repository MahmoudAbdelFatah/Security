using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys = new List<int>(new int[2]);
            int Ya = keyGenration(alpha, xa, q);
            int Yb = keyGenration(alpha, xb, q);
            int keyOfUserA = keyGenration(Yb, xa, q);
            int keyOfUserB = keyGenration(Ya,xb,q);

            keys[0] = keyOfUserA;
            keys[1] = keyOfUserB;

            return keys;
          //  throw new NotImplementedException();
        }

        private int keyGenration(int alpha , int X , int q){
            int result = alpha;
            for (int i = 1; i < X; i++)
            {
                result = (int)((result % q) * (alpha % q)) % q;
            }
            return result;
        }
    }
}

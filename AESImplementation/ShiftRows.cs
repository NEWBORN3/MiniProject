namespace AESImplementation
{
    public static class ShiftRows
    {
        
        public static byte[,] shiftRows(byte[,] roundState)
        {
            byte[] temp = new byte[4];
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[j] = roundState[i, (j + i) % 4];  
                }
                for (int k = 0; k < 4; k++)
                {
                    roundState[i, k] = temp[k];         
                }
            }          
            return roundState;  
        }
    }

}

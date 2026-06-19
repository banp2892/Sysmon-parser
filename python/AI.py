import torch
from torch.utils.data import Dataset

class SysmonDataset(Dataset):
    def __init__(self, data_list, max_len=200):
        """
        data_list: список процессов, где каждый элемент - это 
        список пар (event_id, count)
        """
        self.data_list = data_list
        self.max_len = max_len

    def __len__(self):
        return len(self.data_list)

    def __getitem__(self, idx):
        process_data = self.data_list[idx] # список пар (ID, Count)
        
        # Разделяем на два списка
        ids = [x[0] for x in process_data]
        counts = [x[1] for x in process_data]
        
        # Обрезаем, если слишком длинный, или дополняем нулями (Padding)
        ids = ids[:self.max_len]
        counts = counts[:self.max_len]
        
        padding_len = self.max_len - len(ids)
        ids = ids + [0] * padding_len
        counts = counts + [0] * padding_len
        
        return (
            torch.tensor(ids, dtype=torch.long),
            torch.tensor(counts, dtype=torch.float)
        )
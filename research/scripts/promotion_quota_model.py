"""
Modelo formal en Python de la rutina CPromotionQuotaManager::ConsumeCapacity (VA 0x004D1020..0x004D119E).

Firma original en el ejecutable PE32:
void __thiscall CPromotionQuotaManager::ConsumeCapacity(CPromotionQuotaManager* this, uint32_t target_key, int32_t* inout_requested_amount)
- EAX: CPromotionQuotaManager* (this)
- [ebp + 8]:  target_key (uint32_t)
- [ebp + 0xC]: inout_requested_amount (int32_t*)

Estructura de la entrada en el vector (16 bytes):
- +0x00: data_0 (uint32)
- +0x04: data_4 (uint32)
- +0x08: key / target_object* (uint32)
- +0x0C: available_capacity (int32)

Lógica de cálculo:
1. Comprueba si this->target_list (+0x60) es nulo o si *inout_requested_amount <= 0.
   En ese caso no consume nada y retorna inmediatamente.

2. Itera sobre el vector de entradas (stride 16 bytes) desde begin (+0xF0) hasta end (+0xF4):
   Para cada entrada i:
     Si entry[i].key == target_key:
       avail = entry[i].available_capacity
       req = *inout_requested_amount
       consumed = min(req, avail) if avail > 0 else 0
       
       *inout_requested_amount = req - consumed
       entry[i].available_capacity -= consumed
       
       Si entry[i].target_object != NULL:
         entry[i].target_object.quota -= consumed
         
       Si entry[i].available_capacity <= 0:
         entrada saturada (capacidad agotada)
       break

Retorna el remanente de población no promocionada (*inout_requested_amount) y el estado final de las capacidades.
"""

def consume_promotion_capacity(
    target_key: int,
    requested_amount: int,
    entries: list[dict]
) -> tuple[int, int, list[dict]]:
    """
    entries: lista de dicts con:
      {'key': int, 'capacity': int, 'quota': int}
    
    Retorna:
    (remaining_requested, total_consumed, updated_entries)
    """
    if requested_amount <= 0 or not entries:
        return requested_amount, 0, entries

    rem = requested_amount
    total_consumed = 0
    updated = [dict(e) for e in entries]

    for e in updated:
        if e['key'] == target_key:
            avail = e['capacity']
            if avail > 0:
                consumed = min(rem, avail)
                rem -= consumed
                e['capacity'] -= consumed
                e['quota'] = e.get('quota', 0) - consumed
                total_consumed += consumed
            break

    return rem, total_consumed, updated

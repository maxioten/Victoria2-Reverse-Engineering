"""Transfer arithmetic after the declared bounded destination initialization."""
from integer_model import MASK, signed, trunc_div

MASK32=(1<<32)-1
def signed32(value):
    value &= MASK32
    return value if value < (1<<31) else value-(1<<32)

def clamp_size(value):
    return max(0,min(2000000,signed32(value)))

def transfer(source_size,destination_size,amount_bits,source_balance,destination_balance):
    assert 0<=source_size<=2000000 and destination_size>=0
    amount=min(signed32(amount_bits),source_size)
    destination_new=clamp_size(destination_size+amount)
    result={'amount':amount,'destination_size':destination_new,
            'destination_event_delta':amount,'source_size':source_size,
            'source_event_delta':0,'source_balance':source_balance,'destination_balance':destination_balance,
            'ratio':None,'balance_delta':None}
    if source_size:
        ratio=trunc_div(amount<<30,source_size<<15)
        product=(ratio*source_balance)&MASK
        delta=signed(product)>>15
        result.update(ratio=ratio,balance_delta=delta,
                      source_balance=max(0,signed((source_balance-delta)&MASK)),
                      destination_balance=max(0,signed((destination_balance+delta)&MASK)),
                      source_size=clamp_size(source_size-amount),source_event_delta=-amount)
    return result

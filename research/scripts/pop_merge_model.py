"""Bit-pattern model of the bounded original merge helper; not recovered source."""
from integer_model import MASK, signed, trunc_div
from pop_transfer_model import clamp_size, signed32

def merge(source_size,destination_size,source_attribute,destination_attribute,
          source_balance,destination_balance,event=1):
    assert 0<=source_size<=2000001 and 0<=destination_size<=2000000
    assert event in (1,2,9)
    total=signed32(source_size+destination_size)
    numerator=(((source_size<<15)*source_attribute)&MASK)&~0x7fff
    numerator=(numerator+((((destination_size<<15)*destination_attribute)&MASK)&~0x7fff))&MASK
    attribute=0 if total==0 else trunc_div(signed(numerator),total<<15)&MASK
    balance=(source_balance+destination_balance)&MASK
    if signed(destination_balance)>=0 and signed(source_balance)>0 and signed(balance)<0:
        balance=(1<<63)-1
    elif signed(balance)<0:
        balance=0
    return dict(size=clamp_size(total),previous_size=destination_size or clamp_size(total),attribute=attribute,balance=balance,
                event=event,event_delta=source_size if event<9 else 0,
                balance_event_delta=source_balance)

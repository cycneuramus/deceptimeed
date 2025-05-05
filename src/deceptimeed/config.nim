const
  defaultTbl* = "blocklist"
  defaultSet4* = "bad_ip4"
  defaultSet6* = "bad_ip6"
  defaultChain* = "preraw"
  defaultPrio* = "-300"
  defaultMaxElems* = 100_000

type Config* = object
  tbl*, set4*, set6*, chain*, prio*: string
  maxElems*: int

func defaultConfig*(): Config =
  Config(
    tbl: defaultTbl,
    set4: defaultSet4,
    set6: defaultSet6,
    chain: defaultChain,
    prio: defaultPrio,
    maxElems: defaultMaxElems,
  )

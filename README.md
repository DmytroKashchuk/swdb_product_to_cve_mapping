# This repo shows how we mapped all the products from spice work database to the products present in SpiceWork database!
 
## we are did this using different methods:
- Matching via CNA:  CNA = Vendor and Product in text, it total there are 400 CNA versus 10k technologies
- Matching via CPE: 
- Normilized matching via CPE: 

## How CPE does work:
```cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}```

In our analysis we are doing this:
```cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*```



## Sources
[1] - CPEs explanation: https://www.secopsolution.com/blog/cve-vs-cpe







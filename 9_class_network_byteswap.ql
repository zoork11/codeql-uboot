import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    exists(MacroInvocation inv |
      inv.getMacroName() in ["ntohs", "ntohl", "ntohll"] |
      this = inv.getExpr()
    )
  }
}

from NetworkByteSwap n
select n, "Network byte swap"
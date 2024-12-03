package org.mal_lang.redigoLang.test;

import core.AttackStep;
import java.lang.Override;
import java.lang.String;

public class vm extends Hardware {
  public vm(String name, boolean isSupplyChainAuditingEnabled,
      boolean isHardwareModificationsProtectionEnabled) {
    super(name, isSupplyChainAuditingEnabled, isHardwareModificationsProtectionEnabled);
    assetClassName = "vm";
    AttackStep.allAttackSteps.remove(physicalAccess);
    physicalAccess = new PhysicalAccess(name);
  }

  public vm(String name) {
    super(name);
    assetClassName = "vm";
    AttackStep.allAttackSteps.remove(physicalAccess);
    physicalAccess = new PhysicalAccess(name);
  }

  public vm(boolean isSupplyChainAuditingEnabled,
      boolean isHardwareModificationsProtectionEnabled) {
    this("Anonymous", isSupplyChainAuditingEnabled, isHardwareModificationsProtectionEnabled);
  }

  public vm() {
    this("Anonymous");
  }

  public class PhysicalAccess extends Hardware.PhysicalAccess {
    public PhysicalAccess(String name) {
      super(name);
    }

    @Override
    public double localTtc() {
      return ttcHashMap.get("vm.physicalAccess");
    }
  }
}

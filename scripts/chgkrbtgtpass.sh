#!/bin/sh
#See: https://samba.tranquil.it/doc/en/samba_advanced_methods/samba_reset_krbtgt.html

while (true)
do
  echo "changing Kerberos Ticket Granting Ticket (TGT) password"
  if python3 /scripts/chgkrbtgtpass-v4-15-stable.py | tee /tmp/chgkrbtgtpass.log; then
    echo "SUCCESS: Changed KRBTGT password"
	# Change a second time
	python3 /scripts/chgkrbtgtpass-v4-15-stable.py
  else
    echo "ERROR: Failed chainging KRBTGT password" && exit 1
  fi

  date1="$(date +"%a, %d %b %Y %H:%M:%S %Z")"
  lastset="$(pdbedit -Lv krbtgt | grep "Password last set:")"
  date2="$(echo $lastset | cut -d ':' -f2):$(echo $lastset | cut -d ':' -f3):$(echo $lastset | cut -d ':' -f4)"
  
  echo "Verifying that KRBTGT password has been updated"
  echo "Current date and time"
  echo "$date1"
  echo "$lastset"
  
  # Space as quick fix
  if [ " $date1" = "$date2" ]; then
    echo "Verify OK"
  else
    echo "Verify FAILED"
   ## exit 1
  fi
  #pdbedit -Lv krbtgt # grep password change date => compare to current date => replicate (samba-tool drs replicate <remote_dc> <pdc_dc> dc=mydomain,dc=lan)
sleep 40d
done


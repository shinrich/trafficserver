# Script to run sign.pl script.  Single parameter is number 1 or greater selecting a set of scrip parameters.

# Generate one or more sets of arguments for the sign.pl perl script.
#
cmd_args ()
{
if [[ "$1" = "" ]] ; then
    SELECT=1
else
    SELECT="$1"
fi

FOREVER="$((60 * 60 * 24 * 365 * 1000))"

case "$SELECT" in
1)
    echo "--url http://one.two.three/foo"
    echo "--useparts 1"
    echo "--algorithm 1"
    echo "--duration $FOREVER"
    echo "--keyindex 7"
    echo "--key dqsgopTSM_doT6iAysasQVUKaPykyb6e"
    ;;
2)
    echo "--client 127.0.0.1"
    echo "--url http://four.five.six/foo"
    echo "--useparts=1"
    echo "--algorithm 1"
    echo "--duration $FOREVER"
    echo "--keyindex 13"
    echo "--key CGRDwMO96_vRjFCfks6oxkeV7IdTnA6f"
    ;;
3)
    echo "--url http://seven.eight.nine/foo"
    echo "--useparts=1"
    echo "--algorithm 2"
    echo "--duration $FOREVER"
    echo "--keyindex 0"
    echo "--key hV3wqyq1QxJeF76JkzHf93tuLYv_abw5"
    ;;
*h*)
    ;;
*)
    echo "run_sign.sh: bad seletion parameter" 1>&2
    exit 1
    ;;
esac
}

# Find the path to the sign.pl script in the url_sig (source) directory.
#
find_cmd ()
{
local D T='..'
while [[ ! -d $T/.git ]]
do
  if [[ ! -d $T/.. ]] ; then
    echo "Working directory not in a git repo" 1>&2
    exit 1
  fi
  T="$T/.."
done

for D in $( find $T -name url_sig -type d )
do
    if [[ -x $D/sign.pl ]] ; then
        echo "$D/sign.pl"
        return 0
    fi
done

echo "cannot find sign.pl script" 1>&2
exit 1
}

FOUND=N
echo "$PERL5LIB" | tr ':' ' ' | while read D
do
    if [[ -f $D/Digest/HMAC_MD5.pm ]] ; then
        FOUND=Y
        break
    fi
done

if [[ $FOUND = N ]] ; then
    P=$( find / 2>/dev/null | grep -F Digest/HMAC_MD5.pm | head -1 )
    if [[ ! -f $P ]] ; then
        echo "Cannot find HMAC_MD5.pm" 1>&2
        exit 1
    fi
    export PERL5LIB="$PERL5LIB:$( dirname $( dirname $P ) )"
fi

CMD=$( find_cmd )
if [[ "$?" != 0 ]] ; then
    exit 1
fi

ARGS=$( cmd_args "$1" )
if [[ "$?" != 0 ]] ; then
    exit 1
fi

$CMD $ARGS

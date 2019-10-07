/*
Original Author: Kyle Konrad
Date: 1/19/2011

Modified by: Karl Pierce
Date: 9/18/2017

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

DROP FUNCTION IF EXISTS HMACSHA256;

-- here val is the message generate a HMAC for
DELIMITER //
CREATE FUNCTION HMACSHA256(secret_key VARCHAR(256), val VARCHAR(2048))
  RETURNS CHAR(64) DETERMINISTIC
BEGIN
DECLARE ipad,opad BINARY(64);
DECLARE hexkey CHAR(128);
DECLARE hmac CHAR(64);

SET hexkey = RPAD(HEX(secret_key),128,"0");

IF LENGTH(secret_key) > 64 THEN
   SET hexkey = RPAD(SHA2(secret_key, '256'), 128, "0");
END IF;

SET ipad = UNHEX(CONCAT(
LPAD(CONV(CONV( MID(hexkey,1  ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,17 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,33 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,49 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,65 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,81 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,97 ,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,113,16), 16, 10 ) ^ CONV( '3636363636363636', 16, 10 ),10,16),16,"0")
));

SET opad = UNHEX(CONCAT(
LPAD(CONV(CONV( MID(hexkey,1  ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,17 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,33 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,49 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,65 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,81 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,97 ,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0"),
LPAD(CONV(CONV( MID(hexkey,113,16), 16, 10 ) ^ CONV( '5c5c5c5c5c5c5c5c', 16, 10 ),10,16),16,"0")
));

SET hmac = REPLACE(REPLACE(REPLACE(TO_BASE64(UNHEX(SHA2(CONCAT(opad,UNHEX(SHA2(CONCAT(ipad,val), '256'))), '256'))), '+', '-'), '/', '_'), '=', '');

RETURN hmac;

END //
DELIMITER ;

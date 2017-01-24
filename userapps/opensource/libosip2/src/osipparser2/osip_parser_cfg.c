/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003  Aymeric MOIZARD jack@atosc.org
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#include <osipparser2/osip_port.h>
#include <osipparser2/osip_parser.h>
#include "parser.h"

#ifndef USE_GPERF

static __osip_message_config_t pconfig[NUMBER_OF_HEADERS];

/*
  list of compact header:
  i: Call-ID   => ok
  m: Contact   => ok
  e: Content-Encoding   => ok
  l: Content-Length   => ok
  c: Content-Type   => ok
  f: From   => ok
  s: Subject   => NOT A SUPPORTED HEADER! will be
                 available in the list of unknown headers
  t: To   => ok
  v: Via   => ok
*/
/* This method must be called before using the parser */
int
parser_init ()
{

  pconfig[0].hname = ACCEPT;
  pconfig[0].setheader = (&osip_message_set_accept);
  pconfig[1].hname = ACCEPT_ENCODING;
  pconfig[1].setheader = (&osip_message_set_accept_encoding);
  pconfig[2].hname = ACCEPT_LANGUAGE;
  pconfig[2].setheader = (&osip_message_set_accept_language);
  pconfig[3].hname = ALERT_INFO;
  pconfig[3].setheader = (&osip_message_set_alert_info);
  pconfig[4].hname = ALLOW;
  pconfig[4].setheader = (&osip_message_set_allow);
  pconfig[5].hname = AUTHORIZATION;
  pconfig[5].setheader = (&osip_message_set_authorization);
  pconfig[6].hname = CONTENT_TYPE_SHORT;	/* "l" */
  pconfig[6].setheader = (&osip_message_set_content_type);
  pconfig[7].hname = CALL_ID;
  pconfig[7].setheader = (&osip_message_set_call_id);
  pconfig[8].hname = CALL_INFO;
  pconfig[8].setheader = (&osip_message_set_call_info);
  pconfig[9].hname = CONTACT;
  pconfig[9].setheader = (&osip_message_set_contact);
  pconfig[10].hname = CONTENT_ENCODING;
  pconfig[10].setheader = (&osip_message_set_content_encoding);
  pconfig[11].hname = CONTENT_LENGTH;
  pconfig[11].setheader = (&osip_message_set_content_length);
  pconfig[12].hname = CONTENT_TYPE;
  pconfig[12].setheader = (&osip_message_set_content_type);
  pconfig[13].hname = CSEQ;
  pconfig[13].setheader = (&osip_message_set_cseq);
  pconfig[14].hname = CONTENT_ENCODING_SHORT;	/* "e" */
  pconfig[14].setheader = (&osip_message_set_content_encoding);
  pconfig[15].hname = ERROR_INFO;
  pconfig[15].setheader = (&osip_message_set_error_info);
  pconfig[16].hname = FROM_SHORT;	/* "f" */
  pconfig[16].setheader = (&osip_message_set_from);
  pconfig[17].hname = FROM;
  pconfig[17].setheader = (&osip_message_set_from);
  pconfig[18].hname = CALL_ID_SHORT;	/* "i" */
  pconfig[18].setheader = (&osip_message_set_call_id);
  pconfig[19].hname = CONTENT_LENGTH_SHORT;	/* "l" */
  pconfig[19].setheader = (&osip_message_set_content_length);
  pconfig[20].hname = CONTACT_SHORT;	/* "m" */
  pconfig[20].setheader = (&osip_message_set_contact);
  pconfig[21].hname = MIME_VERSION;
  pconfig[21].setheader = (&osip_message_set_mime_version);
  pconfig[22].hname = PROXY_AUTHENTICATE;
  pconfig[22].setheader = (&osip_message_set_proxy_authenticate);
  pconfig[23].hname = PROXY_AUTHORIZATION;
  pconfig[23].setheader = (&osip_message_set_proxy_authorization);
  pconfig[24].hname = RECORD_ROUTE;
  pconfig[24].setheader = (&osip_message_set_record_route);
  pconfig[25].hname = ROUTE;
  pconfig[25].setheader = (&osip_message_set_route);
  pconfig[26].hname = TO_SHORT;
  pconfig[26].setheader = (&osip_message_set_to);
  pconfig[27].hname = TO;
  pconfig[27].setheader = (&osip_message_set_to);
  pconfig[28].hname = VIA_SHORT;
  pconfig[28].setheader = (&osip_message_set_via);
  pconfig[29].hname = VIA;
  pconfig[29].setheader = (&osip_message_set_via);
  pconfig[30].hname = WWW_AUTHENTICATE;
  pconfig[30].setheader = (&osip_message_set_www_authenticate);

  return 0;
}

/* search the header hname through pconfig[] tab. 
   A quicker algorithm should be used.
   It returns the index of the header in the __osip_message_config_t tab.
*/
int
__osip_message_is_known_header (const char *hname)
{
  size_t length;
  int iinf = 0;
  int isup = NUMBER_OF_HEADERS;
  int i = NUMBER_OF_HEADERS / 2;

  length = strlen (hname);

  for (;;)
    {
      if (i < 0 || i > NUMBER_OF_HEADERS - 1)
	return -1;

      if ((length == strlen (pconfig[i].hname))
	  && osip_strncasecmp (hname, (const char *) pconfig[i].hname,
			       length) == 0)
	return i;

      if (iinf == isup)
	return -1;		/* not found */
      if (iinf == isup - 1)
	{
	  if ((i < NUMBER_OF_HEADERS - 1)
	      && (length == strlen (pconfig[i + 1].hname))
	      && osip_strncasecmp (hname,
				   (const char *) pconfig[i + 1].hname,
				   length) == 0)
	    return i + 1;
	  else
	    return -1;
/* Unreachable code??
	  if ((i > 0) && (length == strlen (pconfig[i - 1].hname))
	      && osip_strncasecmp (hname,
			  (const char *) pconfig[i - 1].hname, length) == 0)
	    return i - 1;
	  else
	    return -1;
*/
	}
      if (0 < osip_strncasecmp (hname,
				(const char *) pconfig[i].hname, length))
	{
	  /* if this is true, search further */
	  iinf = i;
	  if (i == i + (isup - i) / 2)
	    i++;
	  else
	    i = i + (isup - i) / 2;
	}
      else
	{
	  isup = i;
	  if (i == i - (i - iinf) / 2)
	    i--;
	  else
	    i = i - (i - iinf) / 2;
	}
    }				/* end of (while (1)) */
  return -1;
}

#else /* USE_GPERF */
/* C code produced by gperf version 2.7.2 */
/* Command-line: gperf sip.gperf  */

#define TOTAL_KEYWORDS 53
#define MIN_WORD_LENGTH 1
#define MAX_WORD_LENGTH 19
#define MIN_HASH_VALUE 1
#define MAX_HASH_VALUE 132
/* maximum key range = 132, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned char asso_values[] = {
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 20, 133, 25,
  41, 0, 5, 20, 25, 1, 133, 133, 10, 60,
  60, 0, 0, 0, 45, 15, 45, 30, 40, 0,
  133, 15, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133, 133, 133, 133, 133,
  133, 133, 133, 133, 133, 133
};
static const __osip_message_config_t pconfig[133] = {
  {"", NULL},
  {CONTENT_ENCODING_SHORT, &osip_message_set_content_encoding},
  {"", NULL},
  {CALL_ID_SHORT, &osip_message_set_call_id},
  {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL},
  {ERROR_INFO, &osip_message_set_error_info},
  {FROM_SHORT, &osip_message_set_from},
  {IN_REPLY_TO, NULL},
  {PROXY_REQUIRE, NULL},
  {"", NULL}, {"", NULL},
  {WWW_AUTHENTICATE, &osip_message_set_www_authenticate},
  {"", NULL},
  {PROXY_AUTHENTICATE, &osip_message_set_proxy_authenticate},
  {"", NULL}, {"", NULL},
  {CONTENT_LENGTH_SHORT, &osip_message_set_content_length},
  {EXPIRES, NULL},
  {PRIORITY, NULL},
  {"", NULL},
  {ALLOW, &osip_message_set_allow},
  {"", NULL},
  {WARNING, NULL},
  {"", NULL},
  {CSEQ, &osip_message_set_cseq},
  {ALERT_INFO, &osip_message_set_alert_info},
  {SUBJECT_SHORT, NULL},
  {"", NULL}, {"", NULL},
  {CALL_INFO, &osip_message_set_call_info},
  {ACCEPT_LANGUAGE, &osip_message_set_accept_language},
  {"", NULL},
  {CONTENT_TYPE, &osip_message_set_content_type},
  {"", NULL},
  {AUTHENTICATION_INFO, NULL},
  {"", NULL},
  {CONTENT_LANGUAGE, NULL},
  {"", NULL}, {"", NULL}, {"", NULL},
  {SIPDATE, NULL},
  {"", NULL},
  {"to", &osip_message_set_to},
  {"", NULL}, {"", NULL},
  {ROUTE, &osip_message_set_route},
  {CONTENT_TYPE_SHORT, &osip_message_set_content_type},
  {REQUIRE, NULL},
  {REPLY_TO, NULL},
  {TIMESTAMP, NULL},
  {ACCEPT_ENCODING, &osip_message_set_accept_encoding},
  {"", NULL},
  {RECORD_ROUTE, &osip_message_set_record_route},
  {"", NULL}, {"", NULL}, {"", NULL},
  {CONTENT_ENCODING, &osip_message_set_content_encoding},
  {"", NULL},
  {VIA, &osip_message_set_via},
  {CONTENT_LENGTH, &osip_message_set_content_length},
  {SUPPORTED, NULL},
  {SERVER, NULL},
  {SUBJECT, NULL},
  {"", NULL},
  {FROM, &osip_message_set_from},
  {"", NULL},
  {ACCEPT, &osip_message_set_accept},
  {ORGANIZATION, NULL},
  {CALL_ID, &osip_message_set_call_id},
  {"", NULL}, {"", NULL}, {"", NULL},
  {CONTACT, &osip_message_set_contact},
  {"", NULL},
  {PROXY_AUTHORIZATION, &osip_message_set_proxy_authorization},
  {"", NULL},
  {VIA_SHORT, &osip_message_set_via},
  {UNSUPPORTED, NULL},
  {"", NULL}, {"", NULL},
  {USER_AGENT, NULL},
  {MIN_EXPIRES, NULL},
  {MAX_FORWARDS, NULL},
  {"", NULL}, {"", NULL}, {"", NULL},
  {TO_SHORT, &osip_message_set_to},
  {"", NULL},
  {AUTHORIZATION, &osip_message_set_authorization},
  {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"",
									   NULL},
  {RETRY_AFTER, NULL},
  {"", NULL}, {"", NULL},
  {CONTENT_DISPOSITION, NULL},
  {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"",
									   NULL},
  {"", NULL}, {"", NULL},
  {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"",
									   NULL},
  {CONTACT_SHORT, &osip_message_set_contact},
  {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"", NULL}, {"",
									   NULL},
  {"", NULL}, {"", NULL},
  {"", NULL},
  {MIME_VERSION, &osip_message_set_mime_version}
};
static unsigned int
hash (str, len)
     register const char *str;
     register unsigned int len;
{
  return len + asso_values[(unsigned char) str[len - 1]] +
    asso_values[(unsigned char) str[0]];
}

#ifdef __GNUC__
__inline
#endif
  int
in_word_set (str, len)
     register const char *str;
     register unsigned int len;
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
	{
	  register const char *s = pconfig[key].hname;

	  if (*str == *s && !strcmp (str + 1, s + 1)
	      && (pconfig[key].setheader != NULL))
	    return key;
	}
    }
  return -1;
}

int
parser_init ()
{
  return 0;			/* do not need initialization when using gperf */
}

int
__osip_message_is_known_header (const char *hname)
{
  int iLength;

  iLength = strlen (hname);
  return in_word_set (hname, iLength);
}

#endif

/* This method calls the method that is able to parse the header */
int
__osip_message_call_method (int i, osip_message_t * dest, const char *hvalue)
{
  return pconfig[i].setheader (dest, hvalue);
}

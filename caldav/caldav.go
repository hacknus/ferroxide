package caldav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"encoding/xml"
	"path"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/acheong08/ferroxide/protonmail"
	"github.com/acheong08/ferroxide/utils"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
	"github.com/google/uuid"
)

type backend struct {
	c           *protonmail.Client
	privateKeys openpgp.EntityList
	keyCache    map[string]openpgp.EntityList
	locker      sync.Mutex
	username    string
	uidToID     map[string]string
}

var errMissingCalendarKeys = errors.New("calendar keys unavailable")
var errNoReadableEventData = errors.New("no readable event data")

func (b *backend) receiveEvents(events <-chan *protonmail.Event) {
	// TODO
}

func (b *backend) CreateCalendar(ctx context.Context, calendar *caldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("cannot create new calendar"))
}

func readEventCard(event *ical.Event, eventCard protonmail.CalendarEventCard, userKr openpgp.KeyRing, calKr openpgp.KeyRing, keyPacket string) (ical.Props, error) {
	if eventCard.Type.Encrypted() && isEmptyKeyRing(calKr) {
		return nil, errMissingCalendarKeys
	}
	md, err := eventCard.Read(userKr, calKr, keyPacket)
	if err != nil {
		return nil, fmt.Errorf("caldav/readEventCard: error reading event card: (%w)", err)
	}

	data, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("caldav/readEventCard: error reading unverified body: (%w)", err)
	}

	decoded, err := ical.NewDecoder(bytes.NewReader(data)).Decode()
	if err != nil {
		return nil, fmt.Errorf("caldav/readEventCard: error decoding ical data: (%w)", err)
	}

	// The signature can be checked only if md.UnverifiedBody is consumed until
	// EOF
	// TODO: mdc hash mismatch (?)
	/*_, err = io.Copy(io.Discard, md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("caldav/readEventCard: error copying unverified body: (%w)", err)
	}*/

	if err := md.SignatureError; err != nil {
		return nil, fmt.Errorf("caldav/readEventCard: signature error: (%w)", err)
	}

	children := decoded.Events()
	if len(children) != 1 {
		return nil, fmt.Errorf("caldav/readEventCard: expected VCALENDAR to have exactly one VEVENT")
	}
	decodedEvent := &children[0]

	for _, props := range decodedEvent.Props {
		for _, p := range props {
			event.Props.Set(&p)
		}
	}

	return decoded.Props, nil
}

func toIcalCalendar(event *protonmail.CalendarEvent, userKr openpgp.KeyRing, calKr openpgp.KeyRing) (*ical.Calendar, error) {
	merged := ical.NewEvent()
	calProps := ical.Props{}
	skippedEncrypted := false
	// TODO: handle AttendeesEvents and PersonalEvents
	for _, card := range event.SharedEvents {
		if propsMap, err := readEventCard(merged, card, userKr, calKr, event.SharedKeyPacket); err != nil {
			if errors.Is(err, errMissingCalendarKeys) {
				skippedEncrypted = true
				continue
			}
			return nil, fmt.Errorf("caldav/toIcalCalendar: error reading shared event card: (%w)", err)
		} else {
			for name := range propsMap {
				calProps.Set(propsMap.Get(name))
			}
		}
	}

	for _, card := range event.CalendarEvents {
		if propsMap, err := readEventCard(merged, card, userKr, calKr, event.CalendarKeyPacket); err != nil {
			if errors.Is(err, errMissingCalendarKeys) {
				skippedEncrypted = true
				continue
			}
			return nil, fmt.Errorf("caldav/toIcalCalendar: error reading calendar event card: (%w)", err)
		} else {
			for name := range propsMap {
				calProps.Set(propsMap.Get(name))
			}
		}
	}

	if len(merged.Props) == 0 {
		if skippedEncrypted {
			return nil, errNoReadableEventData
		}
		return nil, fmt.Errorf("caldav/toIcalCalendar: empty event")
	}

	for _, notification := range event.Notifications {
		alarm := ical.NewComponent(ical.CompAlarm)

		trigger := ical.NewProp("TRIGGER")
		trigger.SetValueType(ical.ValueDuration)
		trigger.Value = notification.Trigger

		alarm.Props.SetText("ACTION", notification.Type.ToIcalAction())
		alarm.Props.Add(trigger)

		merged.Children = append(merged.Children, alarm)
	}

	// Preserve the VEVENT UID when present; some clients (e.g. Apple Calendar) use it
	// as the resource identifier. Fall back to the Proton event ID only if missing.
	if event.UID != "" {
		merged.Props.SetText("UID", event.UID)
	} else if uidProp := merged.Props.Get("UID"); uidProp == nil || uidProp.Value == "" {
		merged.Props.SetText("UID", event.ID)
	}

	cal := ical.NewCalendar()

	utils.MapCopy(cal.Props, calProps)
	cal.Children = append(cal.Children, merged.Component)

	return cal, nil
}

func isEmptyKeyRing(kr openpgp.KeyRing) bool {
	if kr == nil {
		return true
	}
	if el, ok := kr.(openpgp.EntityList); ok {
		return len(el) == 0
	}
	return false
}

func decryptCalendarKeyring(bootstrap *protonmail.CalendarBootstrap, userKr openpgp.KeyRing) (openpgp.KeyRing, bool, error) {
	calKr, err := bootstrap.DecryptKeyring(userKr)
	if err != nil {
		if errors.Is(err, protonmail.ErrCalendarNoMemberKey) {
			return openpgp.EntityList{}, false, nil
		}
		return nil, false, err
	}
	if isEmptyKeyRing(calKr) {
		return openpgp.EntityList{}, false, nil
	}
	return calKr, true, nil
}

func getCalendarObject(b *backend, calId string, calKr openpgp.KeyRing, event *protonmail.CalendarEvent, settings protonmail.CalendarSettings) (*caldav.CalendarObject, error) {
	author := event.Author
	if author == "" {
		author = b.username
	}
	userKr, exists := b.keyCache[author]
	if !exists {
		if author == "" {
			return nil, fmt.Errorf("caldav/getCalendarObject: missing author email for event %s", event.ID)
		}
		userKeys, err := b.c.GetPublicKeys(author)
		if err != nil {
			return nil, fmt.Errorf("caldav/getCalendarObject: could not get public keys for author %s: (%w)", author, err)
		}

		for _, userKey := range userKeys.Keys {
			userKeyEntity, err := userKey.Entity()
			if err != nil {
				return nil, fmt.Errorf("caldav/getCalendarObject: error converting user key entity: (%w)", err)
			}

			userKr = append(userKr, userKeyEntity)
		}

		b.locker.Lock()
		b.keyCache[author] = userKr
		b.locker.Unlock()
	}

	if event.Notifications == nil {
		if event.FullDay == 0 {
			event.Notifications = settings.DefaultPartDayNotifications
		} else {
			event.Notifications = settings.DefaultFullDayNotifications
		}
	}

	data, err := toIcalCalendar(event, userKr, calKr)
	if err != nil {
		return nil, fmt.Errorf("caldav/getCalendarObject: error converting to iCal calendar: (%w)", err)
	}

	homeSetPath, err := b.CalendarHomeSetPath(nil)
	if err != nil {
		return nil, fmt.Errorf("caldav/getCalendarObject: error getting calendar home set path: (%w)", err)
	}

	resourceID := event.ID
	if event.UID != "" {
		resourceID = event.UID
	}
	co := &caldav.CalendarObject{
		Path:    homeSetPath + calId + formatCalendarObjectPath(resourceID),
		ModTime: time.Unix(int64(event.LastEditTime), 0),
		ETag:    fmt.Sprintf("%X%s", event.LastEditTime, event.ID),
		Data:    data,
	}
	b.locker.Lock()
	if event.ID != "" {
		b.uidToID[event.ID] = event.ID
	}
	if event.UID != "" {
		b.uidToID[event.UID] = event.ID
	}
	b.locker.Unlock()
	return co, nil
}

func formatCalendarObjectPath(id string) string {
	return "/" + id + ".ics"
}

func (b *backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	userPrincipal, err := b.CurrentUserPrincipal(ctx)
	if err != nil {
		return "", fmt.Errorf("caldav/CalendarHomeSetPath: could not get current user principal: (%w)", err)
	}
	return userPrincipal + "calendars/", nil
}

func trimCalendarHome(path, homeSetPath string) (string, error) {
	hs := strings.TrimSuffix(homeSetPath, "/")
	p := strings.TrimSuffix(path, "/")
	if !strings.HasPrefix(p, hs) {
		return "", fmt.Errorf("caldav: path %s is outside home set %s", path, homeSetPath)
	}
	rel := strings.TrimPrefix(p, hs)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "", fmt.Errorf("caldav: empty calendar path for %s", path)
	}
	return rel, nil
}

func parseCalendarID(path, homeSetPath string) (string, error) {
	rel, err := trimCalendarHome(path, homeSetPath)
	if err != nil {
		return "", err
	}
	if strings.Contains(rel, "/") {
		return "", fmt.Errorf("caldav: invalid calendar path %s", path)
	}
	return rel, nil
}

func parseCalendarEventIDs(path, homeSetPath string) (string, string, error) {
	rel, err := trimCalendarHome(path, homeSetPath)
	if err != nil {
		return "", "", err
	}
	if !strings.HasSuffix(rel, ".ics") {
		return "", "", fmt.Errorf("caldav: invalid calendar object path %s", path)
	}
	rel = strings.TrimSuffix(rel, ".ics")
	parts := strings.Split(rel, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("caldav: invalid calendar object path %s", path)
	}
	return parts[0], parts[1], nil
}

func pickCalendarView(cal *protonmail.Calendar, kr openpgp.KeyRing) (*protonmail.CalendarMemberView, bool) {
	if mv, err := protonmail.FindMemberViewFromKeyring(cal.Members, kr); err == nil {
		return mv, true
	}
	if len(cal.Members) == 0 {
		return nil, false
	}
	fallback := cal.Members[0]
	return &fallback, false
}

func (b *backend) ListCalendars(ctx context.Context) ([]caldav.Calendar, error) {
	protonCals, err := b.c.ListCalendars()
	if err != nil {
		return nil, fmt.Errorf("caldav/ListCalendars: error listing ProtonMail calendars: (%w)", err)
	}

	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/ListCalendars: error getting calendar home set path: (%w)", err)
	}

	var cals []caldav.Calendar
	for _, cal := range protonCals {
		calView, _ := pickCalendarView(cal, b.privateKeys)
		if calView == nil {
			continue // Skip calendars we truly can't read
		}

		caldavCal := caldav.Calendar{
			Path:        homeSetPath + cal.ID,
			Name:        calView.Name,
			Description: calView.Description,
		}
		cals = append(cals, caldavCal)
	}
	return cals, nil
}

func (b *backend) GetCalendar(ctx context.Context, path string) (*caldav.Calendar, error) {
	protonCals, err := b.c.ListCalendars()
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendar: error listing ProtonMail calendars: (%w)", err)
	}

	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendar: error getting calendar home set path: (%w)", err)
	}

	id, err := parseCalendarID(path, homeSetPath)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendar: bad path %s: (%w)", path, err)
	}
	for _, cal := range protonCals {
		if cal.ID != id {
			continue
		}

		calView, _ := pickCalendarView(cal, b.privateKeys)
		if calView == nil {
			return nil, fmt.Errorf("caldav/GetCalendar: could not resolve member view for calendar %s", cal.ID)
		}

		caldavCal := caldav.Calendar{
			Path:        homeSetPath + cal.ID,
			Name:        calView.Name,
			Description: calView.Description,
		}

		return &caldavCal, nil
	}
	return nil, errors.New("could not find calendar with path")
}

func (b *backend) GetCalendarObject(ctx context.Context, path string, req *caldav.CalendarCompRequest) (*caldav.CalendarObject, error) {
	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: error getting calendar home set path: (%w)", err)
	}

	calId, evtId, err := parseCalendarEventIDs(path, homeSetPath)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: bad path %s: (%w)", path, err)
	}
	if b.c != nil && b.c.Debug {
		log.Printf("caldav/GetCalendarObject: raw path=%s calId=%s evtId=%s", path, calId, evtId)
	}
	if resolved, ok := resolveEventIDFromCache(b, evtId); ok {
		if b.c != nil && b.c.Debug {
			log.Printf("caldav/GetCalendarObject: cache hit evtId=%s -> %s", evtId, resolved)
		}
		evtId = resolved
	} else if isLikelyUUID(evtId) {
		if b.c != nil && b.c.Debug {
			log.Printf("caldav/GetCalendarObject: evtId looks like UUID, attempting UID resolve: %s", evtId)
		}
		if resolved, resErr := resolveEventIDByUID(b, calId, evtId); resErr == nil {
			if b.c != nil && b.c.Debug {
				log.Printf("caldav/GetCalendarObject: UID resolve success evtId=%s -> %s", evtId, resolved)
			}
			evtId = resolved
		} else {
			if b.c != nil && b.c.Debug {
				log.Printf("caldav/GetCalendarObject: UID resolve failed evtId=%s err=%v", evtId, resErr)
			}
			return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar event not found"))
		}
	}
	event, err := b.c.GetCalendarEvent(calId, evtId)
	if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 2061 {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar event not found"))
	}
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: error getting calendar event (calId: %s, evtId: %s): (%w)", calId, evtId, err)
	}

	bootstrap, err := b.c.BootstrapCalendar(calId)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: error bootstrapping calendar (calId: %s): (%w)", calId, err)
	}

	calKr, hasKeys, err := decryptCalendarKeyring(bootstrap, b.privateKeys)
	if err != nil {
		return nil, fmt.Errorf("caldav/GetCalendarObject: error decrypting keyring: (%w)", err)
	}
	if !hasKeys {
		log.Printf("caldav/GetCalendarObject: calendar %s has no member key; serving read-only unencrypted data", calId)
	}

	co, err := getCalendarObject(b, calId, calKr, event, bootstrap.CalendarSettings)
	if err != nil {
		if errors.Is(err, errNoReadableEventData) {
			return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("calendar event not found"))
		}
		return nil, fmt.Errorf("caldav/GetCalendarObject: error creating calendar object: (%w)", err)
	}

	return co, nil
}

func (b *backend) ListCalendarObjects(ctx context.Context, path string, req *caldav.CalendarCompRequest) ([]caldav.CalendarObject, error) {
	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/ListCalendarObjects: error getting calendar home set path: (%w)", err)
	}

	calId, err := parseCalendarID(path, homeSetPath)
	if err != nil {
		return nil, fmt.Errorf("caldav/ListCalendarObjects: bad path %s: (%w)", path, err)
	}

	events, err := b.c.ListCalendarEvents(calId, nil)
	if err != nil {
		log.Printf("caldav/ListCalendarObjects: error listing calendar events for calId %s: %v", calId, err)
		return nil, fmt.Errorf("caldav/ListCalendarObjects: error listing calendar events for calId %s: (%w)", calId, err)
	}

	bootstrap, err := b.c.BootstrapCalendar(calId)
	if err != nil {
		log.Printf("caldav/ListCalendarObjects: error bootstrapping calendar (calId: %s): %v", calId, err)
		return nil, fmt.Errorf("caldav/ListCalendarObjects: error bootstrapping calendar (calId: %s): (%w)", calId, err)
	}

	calKr, hasKeys, err := decryptCalendarKeyring(bootstrap, b.privateKeys)
	if err != nil {
		log.Printf("caldav/ListCalendarObjects: error decrypting keyring: %v", err)
		return nil, fmt.Errorf("caldav/ListCalendarObjects: error decrypting keyring: (%w)", err)
	}
	if !hasKeys {
		log.Printf("caldav/ListCalendarObjects: calendar %s has no member key; serving read-only unencrypted data", calId)
	}

	var cos []caldav.CalendarObject
	for i, event := range events {
		co, err := getCalendarObject(b, calId, calKr, event, bootstrap.CalendarSettings)
		if err != nil {
			log.Printf("caldav/ListCalendarObjects: skipping event %d (ID: %s) due to error: %v", i, event.ID, err)
			continue
		}
		cos = append(cos, *co)
	}

	return cos, nil
}

func (b *backend) QueryCalendarObjects(ctx context.Context, path string, query *caldav.CalendarQuery) ([]caldav.CalendarObject, error) {
	//TODO caldav backend lib inefficient for not passing query comprequest, possibly bump go-caldav but need to resolve breaking changes on carddav (would also allow create calendar support)
	homeSetPath, err := b.CalendarHomeSetPath(ctx)
	if err != nil {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: error getting calendar home set path: (%w)", err)
	}

	calId, err := parseCalendarID(path, homeSetPath)
	if err != nil {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: bad path %s: (%w)", path, err)
	}

	if query.CompFilter.Name != ical.CompCalendar {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: expected top-level comp to be VCALENDAR")
	}
	if len(query.CompFilter.Comps) != 1 || query.CompFilter.Comps[0].Name != ical.CompEvent {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: expected exactly one nested VEVENT comp")
	}
	cf := &query.CompFilter.Comps[0]

	filter := protonmail.CalendarEventFilter{
		Start:    protonmail.NewTimestamp(cf.Start),
		End:      protonmail.NewTimestamp(cf.End),
		Timezone: cf.Start.Location().String(),
	}

	events, err := b.c.ListCalendarEvents(calId, &filter)
	if err != nil {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: error listing calendar events for calId %s: (%w)", calId, err)
	}

	bootstrap, err := b.c.BootstrapCalendar(calId)
	if err != nil {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: error bootstrapping calendar (calId: %s): (%w)", calId, err)
	}

	calKr, hasKeys, err := decryptCalendarKeyring(bootstrap, b.privateKeys)
	if err != nil {
		return nil, fmt.Errorf("caldav/QueryCalendarObjects: error decrypting keyring: (%w)", err)
	}
	if !hasKeys {
		log.Printf("caldav/QueryCalendarObjects: calendar %s has no member key; serving read-only unencrypted data", calId)
	}

	var cos []caldav.CalendarObject
	for i, event := range events {
		co, err := getCalendarObject(b, calId, calKr, event, bootstrap.CalendarSettings)
		if err != nil {
			if errors.Is(err, errNoReadableEventData) {
				log.Printf("caldav/QueryCalendarObjects: skipping event %d (ID: %s) due to unreadable data", i, event.ID)
				continue
			}
			return nil, fmt.Errorf("caldav/QueryCalendarObjects: error creating calendar object for event %d: (%w)", i, err)
		}

		cos = append(cos, *co)
	}

	return cos, nil
}

func (b *backend) PutCalendarObject(ctx context.Context, path string, calendar *ical.Calendar, opts *caldav.PutCalendarObjectOptions) (loc *caldav.CalendarObject, err error) {
	//TODO: maybe impl opts?
	//TODO: attendees maybe
	homeSetPath, err := b.CalendarHomeSetPath(nil)
	if err != nil {
		return nil, fmt.Errorf("caldav/PutCalendarObject: error getting calendar home set path: (%w)", err)
	}

	calId, evtId, err := parseCalendarEventIDs(path, homeSetPath)
	if err != nil {
		return nil, fmt.Errorf("caldav/PutCalendarObject: bad path %s: (%w)", path, err)
	}
	reqResourceID := evtId

	events := calendar.Events()
	if len(events) != 1 {
		return nil, fmt.Errorf("caldav/PutCalendarObject: expected PUT VCALENDAR to have exactly one VEVENT")
	}
	event := events[0]

	clientUID := ""
	if uidProp := event.Props.Get("UID"); uidProp != nil {
		clientUID = uidProp.Value
	}
	if clientUID == "" && evtId != "" {
		// Preserve client-chosen resource IDs as UID when possible.
		event.Props.SetText("UID", evtId)
		clientUID = evtId
	}
	if resolved, resErr := resolveEventIDByUID(b, calId, evtId); resErr == nil {
		evtId = resolved
	} else if isLikelyUUID(evtId) {
		// Treat unknown UUID resource IDs as creates; avoid passing invalid IDs to Proton.
		evtId = ""
	}

	newEvent, err := b.c.UpdateCalendarEvent(calId, evtId, event, b.privateKeys)
	if err != nil {
		log.Printf("caldav/PutCalendarObject: failed (calId: %s, evtId: %s): %v", calId, evtId, err)
		return nil, fmt.Errorf("caldav/PutCalendarObject: error updating calendar event (calId: %s, evtId: %s): (%w)", calId, evtId, err)
	}

	resourceID := reqResourceID
	if resourceID == "" {
		resourceID = clientUID
	}
	if resourceID == "" {
		resourceID = newEvent.UID
	}
	if resourceID == "" {
		resourceID = newEvent.ID
	}
	path = homeSetPath + calId + formatCalendarObjectPath(resourceID)
	b.locker.Lock()
	if newEvent.ID != "" {
		b.uidToID[newEvent.ID] = newEvent.ID
	}
	if newEvent.UID != "" {
		b.uidToID[newEvent.UID] = newEvent.ID
	}
	if clientUID != "" {
		b.uidToID[clientUID] = newEvent.ID
	}
	if evtId != "" && evtId != newEvent.ID {
		b.uidToID[evtId] = newEvent.ID
	}
	b.locker.Unlock()

	return &caldav.CalendarObject{
		Path:    path,
		ModTime: newEvent.ModifyTime.Time(),
		Data:    calendar,
	}, nil
}

func (b *backend) DeleteCalendarObject(ctx context.Context, path string) error {
	homeSetPath, err := b.CalendarHomeSetPath(nil)
	if err != nil {
		return fmt.Errorf("caldav/DeleteCalendarObject: error getting calendar home set path: (%w)", err)
	}

	calId, evtId, err := parseCalendarEventIDs(path, homeSetPath)
	if err != nil {
		return fmt.Errorf("caldav/DeleteCalendarObject: bad path %s: (%w)", path, err)
	}

	if resolved, resErr := resolveEventIDByUID(b, calId, evtId); resErr == nil {
		evtId = resolved
	}
	if err := b.c.DeleteCalendarEvent(calId, evtId); err != nil {
		return fmt.Errorf("caldav/DeleteCalendarObject: error deleting calendar event (calId: %s, evtId: %s): (%w)", calId, evtId, err)
	}

	return nil
}

func (b *backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return "/caldav/", nil
}

func resolveEventIDFromCache(b *backend, uid string) (string, bool) {
	b.locker.Lock()
	id, ok := b.uidToID[uid]
	b.locker.Unlock()
	return id, ok
}

func resolveEventIDByUID(b *backend, calID string, uid string) (string, error) {
	if uid == "" {
		return "", fmt.Errorf("empty uid")
	}
	b.locker.Lock()
	if resolved, ok := b.uidToID[uid]; ok {
		b.locker.Unlock()
		if b.c != nil && b.c.Debug {
			log.Printf("caldav/resolveEventIDByUID: cache hit uid=%s -> %s", uid, resolved)
		}
		return resolved, nil
	}
	b.locker.Unlock()
	events, err := b.c.ListCalendarEvents(calID, nil)
	if err != nil {
		return "", err
	}
	if b.c != nil && b.c.Debug {
		log.Printf("caldav/resolveEventIDByUID: scanning %d events for uid=%s", len(events), uid)
	}
	for _, event := range events {
		if event.ID == uid {
			if b.c != nil && b.c.Debug {
				log.Printf("caldav/resolveEventIDByUID: uid matches event ID %s", event.ID)
			}
			return event.ID, nil
		}
		if event.UID != "" && strings.EqualFold(event.UID, uid) {
			b.locker.Lock()
			b.uidToID[uid] = event.ID
			b.locker.Unlock()
			if b.c != nil && b.c.Debug {
				log.Printf("caldav/resolveEventIDByUID: uid matches event.UID %s -> %s", event.UID, event.ID)
			}
			return event.ID, nil
		}
	}
	for _, event := range events {
		full, err := b.c.GetCalendarEvent(calID, event.ID)
		if err != nil {
			continue
		}
		if full.UID != "" && strings.EqualFold(full.UID, uid) {
			b.locker.Lock()
			b.uidToID[uid] = full.ID
			b.locker.Unlock()
			if b.c != nil && b.c.Debug {
				log.Printf("caldav/resolveEventIDByUID: uid matches full.UID %s -> %s", full.UID, full.ID)
			}
			return full.ID, nil
		}
	}
	return "", fmt.Errorf("event not found for uid %s", uid)
}

func isLikelyUUID(id string) bool {
	// Simple UUID v4 shape check: 36 chars with hyphens at 8-13-18-23
	if len(id) != 36 {
		return false
	}
	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	return true
}

func resourceIDFromCalendar(cal *ical.Calendar) string {
	if cal != nil {
		events := cal.Events()
		if len(events) == 1 {
			if uidProp := events[0].Props.Get("UID"); uidProp != nil && uidProp.Value != "" {
				return uidProp.Value
			}
		}
	}
	return uuid.NewString()
}

type handler struct {
	backend *backend
	inner   *caldav.Handler
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func shouldLogRequest(r *http.Request, status int) bool {
	if status >= 400 {
		return true
	}
	path := r.URL.Path
	switch r.Method {
	case "PROPFIND", "REPORT", "OPTIONS":
		return path == "/" || strings.HasPrefix(path, "/caldav")
	case "MKCALENDAR", "PUT", "DELETE", "PROPPATCH", "POST":
		return true
	default:
		return false
	}
}

func logRequest(r *http.Request, status int, dur time.Duration) {
	if status == 0 {
		status = http.StatusOK
	}
	if !shouldLogRequest(r, status) {
		return
	}
	ua := r.Header.Get("User-Agent")
	depth := r.Header.Get("Depth")
	log.Printf("caldav/http: %s %s -> %d (%s) depth=%q ua=%q", r.Method, r.URL.Path, status, dur, depth, ua)
}

func writeCollectionStatus(w http.ResponseWriter, href string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(207)
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<multistatus xmlns="DAV:">
  <response>
    <href>%s</href>
    <propstat>
      <prop></prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
</multistatus>`, href)
	_, _ = w.Write([]byte(body))
}

func writeDiscoveryStatus(w http.ResponseWriter, href string, homeSet string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(207)
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:response>
    <D:href>%s</D:href>
    <D:propstat>
      <D:prop>
        <D:current-user-principal><D:href>/caldav/</D:href></D:current-user-principal>
        <C:calendar-home-set><D:href>%s</D:href></C:calendar-home-set>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`, href, homeSet)
	_, _ = w.Write([]byte(body))
}

func writeNeedPrivileges(w http.ResponseWriter, href string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<D:error xmlns:D="DAV:">
  <D:need-privileges>
    <D:resource>
      <D:href>%s</D:href>
      <D:privilege><D:bind/></D:privilege>
    </D:resource>
  </D:need-privileges>
</D:error>`, href)
	_, _ = w.Write([]byte(body))
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w}
	start := time.Now()
	defer func() {
		logRequest(r, rec.status, time.Since(start))
	}()
	w = rec

	// Well-known CalDAV/CardDAV discovery.
	if r.URL.Path == "/.well-known/caldav" {
		http.Redirect(w, r, "/caldav/", http.StatusMovedPermanently)
		return
	}
	if r.URL.Path == "/.well-known/carddav" {
		http.Redirect(w, r, "/carddav/", http.StatusMovedPermanently)
		return
	}

	// Answer OPTIONS on root with DAV headers.
	if r.Method == http.MethodOptions && r.URL.Path == "/" {
		w.Header().Set("DAV", "1, 2, calendar-access")
		w.Header().Set("Allow", "OPTIONS, PROPFIND, REPORT, MKCALENDAR, GET, HEAD, PUT, DELETE, PROPPATCH")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Avoid GET/HEAD on collection paths causing GetCalendarObject errors.
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if r.URL.Path == "/" {
			writeDiscoveryStatus(w, "/", "/caldav/calendars/")
			return
		}
		if r.URL.Path == "/caldav" || r.URL.Path == "/caldav/" {
			writeDiscoveryStatus(w, "/caldav/", "/caldav/calendars/")
			return
		}
		if r.URL.Path == "/caldav/calendars" || r.URL.Path == "/caldav/calendars/" {
			writeCollectionStatus(w, "/caldav/calendars/")
			return
		}
		return
	}
	if r.Method == "PROPFIND" {
		if r.URL.Path == "/" {
			writeDiscoveryStatus(w, "/", "/caldav/calendars/")
			return
		}
	}
	if r.Method == "MKCALENDAR" {
		parent := path.Dir(r.URL.Path)
		if !strings.HasSuffix(parent, "/") {
			parent += "/"
		}
		writeNeedPrivileges(w, parent)
		return
	}
	if r.Method == "PROPPATCH" {
		if h.handlePropPatch(w, r) {
			return
		}
	}
	if r.Method == http.MethodPost {
		if h.handlePost(w, r) {
			return
		}
	}
	h.inner.ServeHTTP(w, r)
}

func (h *handler) handlePropPatch(w http.ResponseWriter, r *http.Request) bool {
	homeSetPath, err := h.backend.CalendarHomeSetPath(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	if !strings.HasPrefix(r.URL.Path, homeSetPath) || strings.HasSuffix(r.URL.Path, ".ics") {
		return false
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return true
	}

	props := parsePropPatchProps(body)
	if len(props) == 0 {
		props = []xml.Name{{Space: "DAV:", Local: "displayname"}}
	}

	response := buildPropPatchResponse(r.URL.Path, props)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(207)
	_, _ = w.Write(response)
	return true
}

func (h *handler) handlePost(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/calendar") {
		return false
	}

	if strings.HasSuffix(r.URL.Path, ".ics") {
		return false
	}

	homeSetPath, err := h.backend.CalendarHomeSetPath(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}

	calID, err := parseCalendarID(r.URL.Path, homeSetPath)
	if err != nil {
		return false
	}

	cal, err := ical.NewDecoder(r.Body).Decode()
	if err != nil {
		http.Error(w, "invalid calendar data", http.StatusBadRequest)
		return true
	}

	resourceID := resourceIDFromCalendar(cal)
	if events := cal.Events(); len(events) == 1 {
		if uidProp := events[0].Props.Get("UID"); uidProp == nil || uidProp.Value == "" {
			events[0].Props.SetText("UID", resourceID)
		}
	}

	path := homeSetPath + calID + formatCalendarObjectPath(resourceID)
	loc, err := h.backend.PutCalendarObject(r.Context(), path, cal, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}

	if loc != nil {
		w.Header().Set("Location", loc.Path)
		if loc.ETag != "" {
			w.Header().Set("ETag", loc.ETag)
		}
	}
	w.WriteHeader(http.StatusCreated)
	return true
}

func parsePropPatchProps(body []byte) []xml.Name {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var props []xml.Name
	inProp := false
	propDepth := 0

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return props
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if !inProp && t.Name.Local == "prop" {
				inProp = true
				propDepth = 0
				continue
			}
			if inProp {
				if propDepth == 0 {
					props = append(props, t.Name)
				}
				propDepth++
			}
		case xml.EndElement:
			if inProp {
				if propDepth > 0 {
					propDepth--
				}
				if propDepth == 0 && t.Name.Local == "prop" {
					inProp = false
				}
			}
		}
	}

	return props
}

func buildPropPatchResponse(href string, props []xml.Name) []byte {
	prefixes := map[string]string{
		"DAV:":                         "D",
		"urn:ietf:params:xml:ns:caldav": "C",
		"http://calendarserver.org/ns/": "CS",
		"http://apple.com/ns/ical/":     "ICAL",
	}

	used := map[string]string{
		"DAV:": "D",
	}
	next := 1
	for _, p := range props {
		ns := p.Space
		if ns == "" {
			ns = "DAV:"
		}
		if _, ok := used[ns]; ok {
			continue
		}
		if pref, ok := prefixes[ns]; ok {
			used[ns] = pref
			continue
		}
		used[ns] = fmt.Sprintf("NS%d", next)
		next++
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString("<D:multistatus")
	for ns, pref := range used {
		b.WriteString(" xmlns:")
		b.WriteString(pref)
		b.WriteString(`="`)
		b.WriteString(ns)
		b.WriteString(`"`)
	}
	b.WriteString(">")

	b.WriteString("<D:response><D:href>")
	escapeXML(&b, href)
	b.WriteString("</D:href><D:propstat><D:prop>")
	for _, p := range props {
		ns := p.Space
		if ns == "" {
			ns = "DAV:"
		}
		pref := used[ns]
		b.WriteString("<")
		b.WriteString(pref)
		b.WriteString(":")
		b.WriteString(p.Local)
		b.WriteString("/>")
	}
	b.WriteString("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>")
	b.WriteString("</D:multistatus>")
	return []byte(b.String())
}

func escapeXML(b *strings.Builder, s string) {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	b.WriteString(buf.String())
}

func NewHandler(c *protonmail.Client, privateKeys openpgp.EntityList, username string, events <-chan *protonmail.Event) http.Handler {
	if len(privateKeys) == 0 {
		panic("ferroxide/caldav: no private key available")
	}

	keyCache := map[string]openpgp.EntityList{username: privateKeys}
	b := &backend{
		c:           c,
		privateKeys: privateKeys,
		keyCache:    keyCache,
		username:    username,
		uidToID:     make(map[string]string),
	}

	if events != nil {
		go b.receiveEvents(events)
	}

	return &handler{
		backend: b,
		inner:   &caldav.Handler{Backend: b},
	}
}

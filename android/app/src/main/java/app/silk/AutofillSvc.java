package app.silk;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.content.Context;
import android.content.Intent;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.Dataset;
import android.service.autofill.FillCallback;
import android.service.autofill.FillContext;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveRequest;
import android.util.Pair;
import android.view.View;
import android.view.ViewStructure;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillValue;
import android.widget.RemoteViews;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Autofill glue. It flattens the screen into JSON, asks Rust (Native.fill) what to do and builds the
 * response. Field detection, matching and the vault all live in Rust.
 */
public class AutofillSvc extends AutofillService {

    @Override
    public void onFillRequest(FillRequest request, CancellationSignal signal, FillCallback callback) {
        try {
            List<FillContext> contexts = request.getFillContexts();
            Form form = Form.parse(contexts.get(contexts.size() - 1).getStructure());
            if (getPackageName().equals(form.pkg)) {
                callback.onSuccess(null); // never fill Silk's own screens
                return;
            }
            String req = form.json();
            JSONObject reply = new JSONObject(Native.fill(req));
            if ("locked".equals(reply.optString("state"))) {
                callback.onSuccess(authResponse(form, req, reply));
            } else {
                callback.onSuccess(responseFrom(this, reply, form.ids));
            }
        } catch (Throwable t) {
            callback.onSuccess(null);
        }
    }

    // Saving new logins from other apps isn't supported yet.
    @Override
    public void onSaveRequest(SaveRequest request, SaveCallback callback) {
        callback.onSuccess();
    }

    /** Locked: show one "Unlock Silk" row that opens AuthActivity, which returns the real response. */
    private FillResponse authResponse(Form form, String req, JSONObject reply) {
        ArrayList<AutofillId> targets = new ArrayList<>();
        if (!reply.isNull("user")) targets.add(form.ids.get(reply.optInt("user")));
        if (!reply.isNull("pass")) targets.add(form.ids.get(reply.optInt("pass")));
        Intent intent = new Intent(this, AuthActivity.class)
                .putExtra("silk_req", req)
                .putParcelableArrayListExtra("silk_ids", form.ids);
        // Mutable because the autofill framework adds its own extras before launching it.
        PendingIntent pending = PendingIntent.getActivity(
                this, 0, intent, PendingIntent.FLAG_CANCEL_CURRENT | PendingIntent.FLAG_MUTABLE);
        RemoteViews label = new RemoteViews(getPackageName(), android.R.layout.simple_list_item_1);
        label.setTextViewText(android.R.id.text1, "Unlock Silk");
        return new FillResponse.Builder()
                .setAuthentication(targets.toArray(new AutofillId[0]), pending.getIntentSender(), label)
                .build();
    }

    /** Turns Rust's {"state":"ok",...} answer into datasets. Returns null when there is nothing to offer. */
    @SuppressWarnings("deprecation")
    static FillResponse responseFrom(Context c, JSONObject reply, List<AutofillId> ids) throws JSONException {
        JSONArray items = reply.optJSONArray("items");
        if (!"ok".equals(reply.optString("state")) || items == null || items.length() == 0) return null;
        AutofillId user = reply.isNull("user") ? null : ids.get(reply.getInt("user"));
        AutofillId pass = reply.isNull("pass") ? null : ids.get(reply.getInt("pass"));
        FillResponse.Builder response = new FillResponse.Builder();
        for (int i = 0; i < items.length(); i++) {
            JSONObject item = items.getJSONObject(i);
            RemoteViews label = new RemoteViews(c.getPackageName(), android.R.layout.simple_list_item_1);
            label.setTextViewText(android.R.id.text1, item.getString("label"));
            Dataset.Builder dataset = new Dataset.Builder(label);
            if (user != null) dataset.setValue(user, AutofillValue.forText(item.getString("user")));
            if (pass != null) dataset.setValue(pass, AutofillValue.forText(item.getString("pass")));
            response.addDataset(dataset.build());
        }
        return response.build();
    }

    static FillResponse responseFor(Context c, String requestJson, List<AutofillId> ids) {
        try {
            return responseFrom(c, new JSONObject(Native.fill(requestJson)), ids);
        } catch (Throwable t) {
            return null;
        }
    }

    /** The screen, flattened: package, web domain and every autofillable text field in on-screen order. */
    static final class Form {
        String pkg = "";
        String domain;
        final ArrayList<AutofillId> ids = new ArrayList<>();
        final JSONArray nodes = new JSONArray();

        static Form parse(AssistStructure structure) {
            Form f = new Form();
            f.pkg = structure.getActivityComponent().getPackageName();
            for (int i = 0; i < structure.getWindowNodeCount(); i++) {
                f.walk(structure.getWindowNodeAt(i).getRootViewNode());
            }
            return f;
        }

        void walk(AssistStructure.ViewNode node) {
            if (domain == null && node.getWebDomain() != null) domain = node.getWebDomain();
            AutofillId id = node.getAutofillId();
            if (id != null && node.getAutofillType() == View.AUTOFILL_TYPE_TEXT) {
                try {
                    JSONObject o = new JSONObject();
                    JSONArray hints = new JSONArray();
                    String[] h = node.getAutofillHints();
                    if (h != null) {
                        for (String s : h) hints.put(s);
                    }
                    o.put("hints", hints);
                    o.put("input", node.getInputType());
                    StringBuilder label = new StringBuilder();
                    append(label, node.getIdEntry());
                    append(label, node.getHint());
                    append(label, node.getContentDescription());
                    ViewStructure.HtmlInfo html = node.getHtmlInfo();
                    if (html != null && html.getAttributes() != null) {
                        for (Pair<String, String> attr : html.getAttributes()) {
                            if ("type".equals(attr.first)) o.put("html", attr.second);
                            if ("autocomplete".equals(attr.first)) o.put("ac", attr.second);
                            if ("name".equals(attr.first) || "id".equals(attr.first)
                                    || "placeholder".equals(attr.first) || "aria-label".equals(attr.first)) {
                                append(label, attr.second);
                            }
                        }
                    }
                    o.put("label", label.toString());
                    nodes.put(o);
                    ids.add(id);
                } catch (JSONException ignored) {
                    // skip this field
                }
            }
            for (int i = 0; i < node.getChildCount(); i++) walk(node.getChildAt(i));
        }

        private static void append(StringBuilder sb, CharSequence s) {
            if (s != null && s.length() > 0) sb.append(s).append(' ');
        }

        String json() throws JSONException {
            JSONObject o = new JSONObject();
            o.put("pkg", pkg);
            o.put("domain", domain == null ? JSONObject.NULL : domain);
            o.put("nodes", nodes);
            return o.toString();
        }
    }
}

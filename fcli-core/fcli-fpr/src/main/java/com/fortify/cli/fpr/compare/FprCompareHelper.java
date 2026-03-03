/*
 * Copyright 2021-2026 Open Text.
 *
 * The only warranties for products and services of Open Text
 * and its affiliates and licensors ("Open Text") are as may
 * be set forth in the express warranty statements accompanying
 * such products and services. Nothing herein should be construed
 * as constituting an additional warranty. Open Text shall not be
 * liable for technical or editorial errors or omissions contained
 * herein. The information contained herein is subject to change
 * without notice.
 */
package com.fortify.cli.fpr.compare;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fortify.cli.aviator.fpr.jaxb.AnalysisInfo;
import com.fortify.cli.aviator.fpr.jaxb.Build;
import com.fortify.cli.aviator.fpr.jaxb.Commandlinetype;
import com.fortify.cli.aviator.fpr.jaxb.Dataflow;
import com.fortify.cli.aviator.fpr.jaxb.DataflowNode;
import com.fortify.cli.aviator.fpr.jaxb.EngineData;
import com.fortify.cli.aviator.fpr.jaxb.Err;
import com.fortify.cli.aviator.fpr.jaxb.ErrMsg;
import com.fortify.cli.aviator.fpr.jaxb.FVDL;
import com.fortify.cli.aviator.fpr.jaxb.FileList;
import com.fortify.cli.aviator.fpr.jaxb.LOC;
import com.fortify.cli.aviator.fpr.jaxb.NameValuePair;
import com.fortify.cli.aviator.fpr.jaxb.Propertylist;
import com.fortify.cli.aviator.fpr.jaxb.RulePackList;
import com.fortify.cli.aviator.fpr.jaxb.SourceLocationType;
import com.fortify.cli.aviator.fpr.jaxb.SourceRefBaseType;
import com.fortify.cli.aviator.fpr.jaxb.TimeStamp;
import com.fortify.cli.aviator.fpr.jaxb.Unified;
import com.fortify.cli.aviator.fpr.jaxb.UnifiedNode;
import com.fortify.cli.aviator.fpr.jaxb.UnifiedTrace;
import com.fortify.cli.aviator.fpr.jaxb.Vulnerabilities;
import com.fortify.cli.aviator.fpr.jaxb.Vulnerability;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;

public class FprCompareHelper {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private static String normalizeUuids(String value) {
        return value == null ? null : UUID_PATTERN.matcher(value).replaceAll("<UUID>");
    }

    public static JsonNode compare(Path baselinePath, Path comparisonPath) {
        try {
            FVDL baselineFvdl = unmarshalFvdl(baselinePath);
            FVDL comparisonFvdl = unmarshalFvdl(comparisonPath);

            ObjectNode root = mapper.createObjectNode();
            root.set("metadata", buildMetadata(baselinePath, comparisonPath, baselineFvdl, comparisonFvdl));
            root.set("engine", buildEngine(baselineFvdl, comparisonFvdl));
            root.set("rulePacks", buildRulePacks(baselineFvdl, comparisonFvdl));
            root.set("commandLine", buildCommandLine(baselineFvdl, comparisonFvdl));
            root.set("properties", buildProperties(baselineFvdl, comparisonFvdl));
            Set<String> baseFiles = extractFileNames(baselineFvdl);
            Set<String> compFiles = extractFileNames(comparisonFvdl);
            Set<String> addedFiles = diff(compFiles, baseFiles);
            Set<String> removedFiles = diff(baseFiles, compFiles);

            root.set("files", buildFiles(baseFiles, compFiles, addedFiles, removedFiles));
            root.set("loc", buildLoc(baselineFvdl, comparisonFvdl));
            root.set("errors", buildErrors(baselineFvdl, comparisonFvdl));
            root.set("vulnerabilities", buildVulnerabilities(baselineFvdl, comparisonFvdl, addedFiles, removedFiles));

            return root;
        } catch (Exception e) {
            throw new RuntimeException("Failed to compare FPR files", e);
        }
    }

    private static FVDL unmarshalFvdl(Path fprPath) throws JAXBException, IOException {
        java.nio.file.FileSystem zipfs = java.nio.file.FileSystems.newFileSystem(fprPath, (ClassLoader) null);
        try {
            Path fvdlPath = zipfs.getPath("/audit.fvdl");
            if (!Files.exists(fvdlPath)) {
                zipfs.close();
                throw new IllegalArgumentException("FPR file does not contain audit.fvdl: " + fprPath);
            }
            try (InputStream fis = Files.newInputStream(fvdlPath)) {
                JAXBContext jaxbContext = JAXBContext.newInstance(FVDL.class);
                Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
                javax.xml.stream.XMLInputFactory xmlInputFactory = javax.xml.stream.XMLInputFactory.newInstance();
                xmlInputFactory.setProperty(javax.xml.stream.XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
                xmlInputFactory.setProperty(javax.xml.stream.XMLInputFactory.SUPPORT_DTD, false);
                javax.xml.stream.XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(fis);
                FVDL fvdl = (FVDL) unmarshaller.unmarshal(xmlStreamReader);
                zipfs.close();
                return fvdl;
            } catch (javax.xml.stream.XMLStreamException e) {
                zipfs.close();
                throw new JAXBException("Error creating secure XML stream reader", e);
            }
        } catch (JAXBException | IOException e) {
            try { zipfs.close(); } catch (IOException ignored) {}
            throw e;
        }
    }

    private static ObjectNode buildMetadata(Path baselinePath, Path comparisonPath, FVDL baseline, FVDL comparison) {
        ObjectNode metadata = mapper.createObjectNode();
        metadata.set("baseline", buildScanInfo(baselinePath, baseline));
        metadata.set("comparison", buildScanInfo(comparisonPath, comparison));
        return metadata;
    }

    private static ObjectNode buildScanInfo(Path path, FVDL fvdl) {
        ObjectNode info = mapper.createObjectNode();
        info.put("file", path.getFileName().toString());
        Build build = fvdl.getBuild();
        if (build != null) {
            info.put("buildId", nullSafe(build.getBuildID()));
            if (build.getScanTime() != null && build.getScanTime().getValue() != null) {
                info.put("scanTime", build.getScanTime().getValue().longValue());
            }
            info.put("project", nullSafe(build.getProject()));
            info.put("version", nullSafe(build.getVersion()));
        }
        TimeStamp ts = fvdl.getCreatedTS();
        if (ts != null) {
            String dateStr = ts.getDate() != null ? ts.getDate().toString() : "";
            String timeStr = ts.getTime() != null ? ts.getTime().toString() : "";
            if (!dateStr.isEmpty() || !timeStr.isEmpty()) {
                info.put("scanDate", (dateStr + " " + timeStr).trim());
            }
        }
        return info;
    }

    private static ObjectNode buildEngine(FVDL baseline, FVDL comparison) {
        ObjectNode engine = mapper.createObjectNode();
        String baseVer = getEngineVersion(baseline);
        String compVer = getEngineVersion(comparison);
        engine.put("baselineVersion", nullSafe(baseVer));
        engine.put("comparisonVersion", nullSafe(compVer));
        engine.put("changed", !Objects.equals(baseVer, compVer));
        return engine;
    }

    private static String getEngineVersion(FVDL fvdl) {
        EngineData ed = fvdl.getEngineData();
        return ed != null ? ed.getEngineVersion() : null;
    }

    private static ObjectNode buildRulePacks(FVDL baseline, FVDL comparison) {
        Set<String> baseRulePacks = extractRulePackNames(baseline);
        Set<String> compRulePacks = extractRulePackNames(comparison);

        ObjectNode node = mapper.createObjectNode();
        node.set("added", toArrayNode(diff(compRulePacks, baseRulePacks)));
        node.set("removed", toArrayNode(diff(baseRulePacks, compRulePacks)));
        node.set("common", toArrayNode(intersect(baseRulePacks, compRulePacks)));
        return node;
    }

    private static Set<String> extractRulePackNames(FVDL fvdl) {
        EngineData ed = fvdl.getEngineData();
        if (ed == null || ed.getRulePacks() == null) return Collections.emptySet();
        Set<String> names = new LinkedHashSet<>();
        for (RulePackList.RulePack rp : ed.getRulePacks().getRulePack()) {
            String name = extractRulePackField(rp, "Name");
            String version = extractRulePackField(rp, "Version");
            if (name != null) {
                names.add(version != null ? name + " " + version : name);
            }
        }
        return names;
    }

    @SuppressWarnings("unchecked")
    private static String extractRulePackField(RulePackList.RulePack rp, String fieldName) {
        for (Serializable item : rp.getContent()) {
            if (item instanceof JAXBElement) {
                JAXBElement<String> elem = (JAXBElement<String>) item;
                if (elem.getName().getLocalPart().equals(fieldName)) {
                    return elem.getValue();
                }
            }
        }
        return null;
    }

    private static ObjectNode buildCommandLine(FVDL baseline, FVDL comparison) {
        List<String> baseArgs = extractCommandLineArgs(baseline);
        List<String> compArgs = extractCommandLineArgs(comparison);

        Set<String> baseNorm = baseArgs.stream().map(FprCompareHelper::normalizeUuids)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> compNorm = compArgs.stream().map(FprCompareHelper::normalizeUuids)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> addedNorm = diff(compNorm, baseNorm);
        Set<String> removedNorm = diff(baseNorm, compNorm);

        ObjectNode node = mapper.createObjectNode();
        node.set("baseline", toArrayNode(baseArgs));
        node.set("comparison", toArrayNode(compArgs));
        node.set("added", toArrayNode(compArgs.stream()
                .filter(a -> addedNorm.contains(normalizeUuids(a)))
                .collect(Collectors.toList())));
        node.set("removed", toArrayNode(baseArgs.stream()
                .filter(a -> removedNorm.contains(normalizeUuids(a)))
                .collect(Collectors.toList())));
        return node;
    }

    private static List<String> extractCommandLineArgs(FVDL fvdl) {
        EngineData ed = fvdl.getEngineData();
        if (ed == null) return Collections.emptyList();
        Commandlinetype cmdLine = ed.getCommandLine();
        if (cmdLine == null) return Collections.emptyList();
        return cmdLine.getArgument();
    }

    private static ObjectNode buildProperties(FVDL baseline, FVDL comparison) {
        Map<String, String> baseProps = extractProperties(baseline);
        Map<String, String> compProps = extractProperties(comparison);

        ObjectNode node = mapper.createObjectNode();
        ObjectNode added = mapper.createObjectNode();
        ObjectNode removed = mapper.createObjectNode();
        ObjectNode changed = mapper.createObjectNode();
        ObjectNode common = mapper.createObjectNode();

        Set<String> allKeys = new LinkedHashSet<>();
        allKeys.addAll(baseProps.keySet());
        allKeys.addAll(compProps.keySet());

        for (String key : allKeys) {
            String baseVal = baseProps.get(key);
            String compVal = compProps.get(key);
            if (baseVal == null) {
                added.put(key, compVal);
            } else if (compVal == null) {
                removed.put(key, baseVal);
            } else if (!Objects.equals(normalizeUuids(baseVal), normalizeUuids(compVal))) {
                ObjectNode diff = mapper.createObjectNode();
                diff.put("baseline", baseVal);
                diff.put("comparison", compVal);
                changed.set(key, diff);
            } else {
                common.put(key, baseVal);
            }
        }

        node.set("added", added);
        node.set("removed", removed);
        node.set("changed", changed);
        node.set("common", common);
        return node;
    }

    private static Map<String, String> extractProperties(FVDL fvdl) {
        EngineData ed = fvdl.getEngineData();
        if (ed == null) return Collections.emptyMap();
        Map<String, String> props = new LinkedHashMap<>();
        for (Propertylist pl : ed.getProperties()) {
            for (NameValuePair nvp : pl.getProperty()) {
                String prefix = pl.getType() != null ? pl.getType() + "." : "";
                props.put(prefix + nvp.getName(), nvp.getValue());
            }
        }
        return props;
    }

    private static ObjectNode buildFiles(Set<String> baseFiles, Set<String> compFiles,
                                          Set<String> addedFiles, Set<String> removedFiles) {
        ObjectNode node = mapper.createObjectNode();
        node.put("baselineCount", baseFiles.size());
        node.put("comparisonCount", compFiles.size());
        node.set("added", toArrayNode(addedFiles));
        node.set("removed", toArrayNode(removedFiles));
        return node;
    }

    @SuppressWarnings("unchecked")
    private static Set<String> extractFileNames(FVDL fvdl) {
        Build build = fvdl.getBuild();
        if (build == null || build.getSourceFiles() == null) return Collections.emptySet();
        Set<String> names = new LinkedHashSet<>();
        for (FileList.File f : build.getSourceFiles().getFile()) {
            for (Object content : f.getContent()) {
                if (content instanceof JAXBElement) {
                    JAXBElement<String> elem = (JAXBElement<String>) content;
                    if ("Name".equals(elem.getName().getLocalPart())) {
                        names.add(elem.getValue());
                    }
                }
            }
        }
        return names;
    }

    private static ObjectNode buildLoc(FVDL baseline, FVDL comparison) {
        long baseLoc = extractTotalLoc(baseline);
        long compLoc = extractTotalLoc(comparison);

        ObjectNode node = mapper.createObjectNode();
        node.put("baseline", baseLoc);
        node.put("comparison", compLoc);
        node.put("delta", compLoc - baseLoc);
        return node;
    }

    private static long extractTotalLoc(FVDL fvdl) {
        Build build = fvdl.getBuild();
        if (build == null) return 0;
        long total = 0;
        for (LOC loc : build.getLOC()) {
            total += loc.getValue();
        }
        return total;
    }

    private static ObjectNode buildErrors(FVDL baseline, FVDL comparison) {
        List<ObjectNode> baseErrors = extractErrors(baseline);
        List<ObjectNode> compErrors = extractErrors(comparison);

        Set<String> baseKeys = baseErrors.stream().map(e -> errorKey(e)).collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> compKeys = compErrors.stream().map(e -> errorKey(e)).collect(Collectors.toCollection(LinkedHashSet::new));

        Map<String, ObjectNode> baseMap = new LinkedHashMap<>();
        baseErrors.forEach(e -> baseMap.put(errorKey(e), e));
        Map<String, ObjectNode> compMap = new LinkedHashMap<>();
        compErrors.forEach(e -> compMap.put(errorKey(e), e));

        ObjectNode node = mapper.createObjectNode();
        node.set("baseline", mapper.valueToTree(baseErrors));
        node.set("comparison", mapper.valueToTree(compErrors));

        ArrayNode added = mapper.createArrayNode();
        for (String key : diff(compKeys, baseKeys)) {
            added.add(compMap.get(key));
        }
        node.set("added", added);

        ArrayNode removed = mapper.createArrayNode();
        for (String key : diff(baseKeys, compKeys)) {
            removed.add(baseMap.get(key));
        }
        node.set("removed", removed);
        return node;
    }

    private static String errorKey(ObjectNode err) {
        return normalizeUuids(err.path("code").asText("") + "|" + err.path("message").asText(""));
    }

    private static List<ObjectNode> extractErrors(FVDL fvdl) {
        EngineData ed = fvdl.getEngineData();
        if (ed == null) return Collections.emptyList();
        ErrMsg errors = ed.getErrors();
        if (errors == null) return Collections.emptyList();
        List<ObjectNode> result = new ArrayList<>();
        for (Err err : errors.getError()) {
            ObjectNode errNode = mapper.createObjectNode();
            errNode.put("code", nullSafe(err.getCode()));
            errNode.put("message", nullSafe(err.getValue()));
            result.add(errNode);
        }
        return result;
    }

    private static ObjectNode buildVulnerabilities(FVDL baseline, FVDL comparison,
                                                    Set<String> addedFiles, Set<String> removedFiles) {
        List<VulnInfo> baseVulns = extractVulnInfos(baseline);
        List<VulnInfo> compVulns = extractVulnInfos(comparison);

        Map<String, VulnInfo> baseMap = new LinkedHashMap<>();
        baseVulns.forEach(v -> baseMap.put(v.instanceID, v));
        Map<String, VulnInfo> compMap = new LinkedHashMap<>();
        compVulns.forEach(v -> compMap.put(v.instanceID, v));

        Set<String> baseIds = baseMap.keySet();
        Set<String> compIds = compMap.keySet();
        Set<String> newIds = diff(compIds, baseIds);
        Set<String> removedIds = diff(baseIds, compIds);
        Set<String> commonIds = intersect(baseIds, compIds);

        ObjectNode node = mapper.createObjectNode();
        node.put("baselineTotal", baseVulns.size());
        node.put("comparisonTotal", compVulns.size());

        List<VulnInfo> newList = newIds.stream().map(compMap::get)
                .sorted((a, b) -> nullSafe(a.sink).compareToIgnoreCase(nullSafe(b.sink)))
                .collect(Collectors.toList());
        ArrayNode newArr = mapper.createArrayNode();
        for (VulnInfo v : newList) {
            ObjectNode vn = v.toJson();
            vn.put("reason", addedFiles.contains(v.sinkFile()) ? "file_added" : "new");
            newArr.add(vn);
        }
        node.set("new", newArr);

        List<VulnInfo> removedList = removedIds.stream().map(baseMap::get)
                .sorted((a, b) -> nullSafe(a.sink).compareToIgnoreCase(nullSafe(b.sink)))
                .collect(Collectors.toList());
        ArrayNode removedArr = mapper.createArrayNode();
        for (VulnInfo v : removedList) {
            ObjectNode vn = v.toJson();
            vn.put("reason", removedFiles.contains(v.sinkFile()) ? "file_removed" : "fixed");
            removedArr.add(vn);
        }
        node.set("removed", removedArr);

        node.put("common", commonIds.size());

        // Category summary
        Map<String, int[]> categoryCounts = new LinkedHashMap<>();
        for (VulnInfo v : baseVulns) {
            categoryCounts.computeIfAbsent(v.category, k -> new int[4])[0]++;
        }
        for (VulnInfo v : compVulns) {
            categoryCounts.computeIfAbsent(v.category, k -> new int[4])[1]++;
        }
        for (String id : newIds) {
            VulnInfo v = compMap.get(id);
            categoryCounts.computeIfAbsent(v.category, k -> new int[4])[2]++;
        }
        for (String id : removedIds) {
            VulnInfo v = baseMap.get(id);
            categoryCounts.computeIfAbsent(v.category, k -> new int[4])[3]++;
        }

        ObjectNode catSummary = mapper.createObjectNode();
        for (Map.Entry<String, int[]> entry : categoryCounts.entrySet()) {
            int[] counts = entry.getValue();
            ObjectNode catNode = mapper.createObjectNode();
            catNode.put("baseline", counts[0]);
            catNode.put("comparison", counts[1]);
            catNode.put("new", counts[2]);
            catNode.put("removed", counts[3]);
            catSummary.set(entry.getKey(), catNode);
        }
        node.set("categorySummary", catSummary);

        return node;
    }

    private static List<VulnInfo> extractVulnInfos(FVDL fvdl) {
        Vulnerabilities vulns = fvdl.getVulnerabilities();
        if (vulns == null) return Collections.emptyList();
        List<VulnInfo> result = new ArrayList<>();
        for (Vulnerability v : vulns.getVulnerability()) {
            result.add(VulnInfo.from(v));
        }
        return result;
    }

    private static class VulnInfo {
        final String instanceID;
        final String classID;
        final String category;
        final String source;
        final String sink;
        final double severity;

        VulnInfo(String instanceID, String classID, String category, String source, String sink, double severity) {
            this.instanceID = instanceID;
            this.classID = classID;
            this.category = category != null ? category : "Unknown";
            this.source = source;
            this.sink = sink;
            this.severity = severity;
        }

        static VulnInfo from(Vulnerability v) {
            String instanceID = null;
            String classID = null;
            String category = null;
            double severity = 0.0;
            String source = null;
            String sink = null;

            if (v.getInstanceInfo() != null) {
                instanceID = v.getInstanceInfo().getInstanceID();
                if (v.getInstanceInfo().getInstanceSeverity() != null) {
                    severity = v.getInstanceInfo().getInstanceSeverity().doubleValue();
                }
            }
            if (v.getClassInfo() != null) {
                classID = v.getClassInfo().getClassID();
                category = v.getClassInfo().getType();
            }

            AnalysisInfo ai = v.getAnalysisInfo();
            if (ai != null) {
                if (ai.getUnified() != null) {
                    Unified unified = ai.getUnified();
                    if (unified.getTrace() != null && !unified.getTrace().isEmpty()) {
                        UnifiedTrace trace = unified.getTrace().get(0);
                        if (trace.getPrimary() != null) {
                            List<UnifiedTrace.Primary.Entry> entries = trace.getPrimary().getEntry();
                            if (entries != null && !entries.isEmpty()) {
                                source = formatUnifiedNodeLocation(entries.get(0).getNode());
                                sink = formatUnifiedNodeLocation(entries.get(entries.size() - 1).getNode());
                            }
                        }
                    }
                } else if (ai.getDataflow() != null) {
                    Dataflow df = ai.getDataflow();
                    source = formatDataflowNodeLocation(df.getSource());
                    sink = formatDataflowNodeLocation(df.getSink());
                }
            }

            if (instanceID == null) {
                instanceID = classID != null ? classID : "unknown-" + v.hashCode();
            }
            return new VulnInfo(instanceID, classID, category, source, sink, severity);
        }

        private static String formatUnifiedNodeLocation(UnifiedNode node) {
            if (node == null) return null;
            SourceLocationType loc = node.getSourceLocation();
            if (loc == null) return null;
            String path = loc.getPath();
            Integer line = loc.getLine();
            if (path == null) return null;
            return line != null ? path + ":" + line : path;
        }

        private static String formatDataflowNodeLocation(DataflowNode node) {
            if (node == null || node.getSourceRef() == null) return null;
            SourceRefBaseType ref = null;
            if (node.getSourceRef().getFunctionCall() != null) {
                ref = node.getSourceRef().getFunctionCall();
            } else if (node.getSourceRef().getFunctionEntry() != null) {
                ref = node.getSourceRef().getFunctionEntry();
            } else if (node.getSourceRef().getStatement() != null) {
                ref = node.getSourceRef().getStatement();
            }
            if (ref == null || ref.getSourceLocation() == null) return null;
            SourceLocationType loc = ref.getSourceLocation();
            String path = loc.getPath();
            Integer line = loc.getLine();
            if (path == null) return null;
            return line != null ? path + ":" + line : path;
        }

        String sinkFile() {
            if (sink == null) return null;
            int colon = sink.lastIndexOf(':');
            return colon > 0 ? sink.substring(0, colon) : sink;
        }

        ObjectNode toJson() {
            ObjectNode node = mapper.createObjectNode();
            node.put("instanceID", instanceID);
            if (category != null) node.put("category", category);
            if (sink != null) node.put("sink", sink);
            node.put("severity", severity);
            return node;
        }
    }

    // --- Utility methods ---

    private static <T> Set<T> diff(Set<T> a, Set<T> b) {
        Set<T> result = new LinkedHashSet<>(a);
        result.removeAll(b);
        return result;
    }

    private static <T> Set<T> intersect(Set<T> a, Set<T> b) {
        Set<T> result = new LinkedHashSet<>(a);
        result.retainAll(b);
        return result;
    }

    private static ArrayNode toArrayNode(Iterable<String> items) {
        ArrayNode arr = mapper.createArrayNode();
        for (String item : items) {
            arr.add(item);
        }
        return arr;
    }

    private static String nullSafe(String value) {
        return value != null ? value : "";
    }
}

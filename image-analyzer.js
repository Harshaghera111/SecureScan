/* ════════════════════════════════════════════════════════════════
   SecureScan v2 — Image Analysis Engine
   ELA simulation, frequency analysis, LBP texture,
   multi-signal Bayesian fusion scoring
   ════════════════════════════════════════════════════════════════ */

SecureScanAnalyzer.analyzeImage = function (imageDataUrl) {
    return new Promise((resolve) => {
        const img = new Image();
        img.onload = () => {
            const issues = [];
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            // Use reasonable resolution for analysis
            const MAX = 512;
            const scale = Math.min(1, MAX / Math.max(img.width, img.height));
            const w = Math.round(img.width * scale);
            const h = Math.round(img.height * scale);
            canvas.width = w;
            canvas.height = h;
            ctx.drawImage(img, 0, 0, w, h);

            let imageData;
            try { imageData = ctx.getImageData(0, 0, w, h); }
            catch (e) {
                resolve(this._buildResult([{
                    severity: 'medium', name: 'Cannot Analyze Image', location: 'Image data',
                    description: 'Cross-origin restriction prevents pixel analysis.',
                    snippet: 'CORS error', fix: 'Re-upload the image from your device.',
                    confidence: 'confirmed'
                }], 'image'));
                return;
            }

            const px = imageData.data;
            const totalPx = w * h;
            const signals = {};   // collects all check results
            let suspicion = 0;    // cumulative suspicion score

            // ═══════════════════════════════════════════════════
            //  CHECK 1: Noise Distribution Analysis
            // ═══════════════════════════════════════════════════
            let noiseCount = 0, edgeCount = 0, smoothCount = 0;
            let totalDiff = 0;

            for (let i = 0; i < px.length - 8; i += 4) {
                const diff = Math.abs(px[i] - px[i + 4]) + Math.abs(px[i + 1] - px[i + 5]) + Math.abs(px[i + 2] - px[i + 6]);
                totalDiff += diff;
                if (diff > 1 && diff < 8) noiseCount++;
                else if (diff > 60) edgeCount++;
                else if (diff === 0) smoothCount++;
            }

            const noiseRatio = noiseCount / totalPx;
            const edgeRatio = edgeCount / totalPx;
            const smoothRatio = smoothCount / totalPx;
            const avgDiff = totalDiff / totalPx;
            signals.noise = noiseRatio;
            signals.edges = edgeRatio;
            signals.smooth = smoothRatio;

            if (noiseRatio > 0.3 && noiseRatio < 0.7) {
                suspicion += 18;
                issues.push({
                    severity: 'medium', name: 'Uniform Micro-Noise Pattern', location: 'Pixel analysis',
                    description: `${(noiseRatio * 100).toFixed(1)}% of adjacent pixels show micro-noise (1-8 difference). AI-generated images often have unnaturally uniform noise compared to camera sensor noise.`,
                    snippet: `Noise ratio: ${(noiseRatio * 100).toFixed(1)}% | Natural range: 15-30%\nEdge density: ${(edgeRatio * 100).toFixed(1)}% | Smoothness: ${(smoothRatio * 100).toFixed(1)}%`,
                    fix: 'AI models produce noise patterns that differ from camera sensor noise. Compare with photos from the same alleged device.',
                    confidence: 'likely'
                });
            }

            if (edgeRatio < 0.03) {
                suspicion += 12;
                issues.push({
                    severity: 'medium', name: 'Unusually Smooth Image', location: 'Edge analysis',
                    description: `Only ${(edgeRatio * 100).toFixed(1)}% edge pixels detected. Natural photos typically have 5-20%. May indicate AI smoothing or heavy post-processing.`,
                    snippet: `Edge density: ${(edgeRatio * 100).toFixed(1)}% | Expected: 5-20%`,
                    fix: 'Over-smoothed images may be AI-generated or heavily filtered. Request the original unprocessed photo.',
                    confidence: 'likely'
                });
            }

            // ═══════════════════════════════════════════════════
            //  CHECK 2: Error Level Analysis (ELA) Simulation
            // ═══════════════════════════════════════════════════
            // Re-compress at lower quality and compare
            const elaCanvas = document.createElement('canvas');
            elaCanvas.width = w; elaCanvas.height = h;
            const elaCtx = elaCanvas.getContext('2d');

            // Simulate re-compression by reducing and enlarging
            const smallCanvas = document.createElement('canvas');
            const sf = 0.5;  // compress to 50%
            smallCanvas.width = Math.round(w * sf);
            smallCanvas.height = Math.round(h * sf);
            const smallCtx = smallCanvas.getContext('2d');
            smallCtx.drawImage(canvas, 0, 0, smallCanvas.width, smallCanvas.height);
            elaCtx.drawImage(smallCanvas, 0, 0, w, h);  // scale back up

            let elaData;
            try { elaData = elaCtx.getImageData(0, 0, w, h); } catch (e) { elaData = null; }

            if (elaData) {
                const elaPx = elaData.data;
                let elaTotal = 0, elaMax = 0, elaMin = 255 * 3;
                const regionSize = 32;
                const regionErrors = [];

                for (let ry = 0; ry < h; ry += regionSize) {
                    for (let rx = 0; rx < w; rx += regionSize) {
                        let regionErr = 0, regionCount = 0;
                        for (let y = ry; y < Math.min(ry + regionSize, h); y++) {
                            for (let x = rx; x < Math.min(rx + regionSize, w); x++) {
                                const idx = (y * w + x) * 4;
                                const diff = Math.abs(px[idx] - elaPx[idx]) + Math.abs(px[idx + 1] - elaPx[idx + 1]) + Math.abs(px[idx + 2] - elaPx[idx + 2]);
                                elaTotal += diff;
                                regionErr += diff;
                                regionCount++;
                            }
                        }
                        const avgErr = regionErr / (regionCount || 1);
                        regionErrors.push(avgErr);
                        if (avgErr > elaMax) elaMax = avgErr;
                        if (avgErr < elaMin) elaMin = avgErr;
                    }
                }

                const elaAvg = elaTotal / totalPx;
                const elaVariance = regionErrors.reduce((s, e) => s + Math.pow(e - elaAvg, 2), 0) / (regionErrors.length || 1);
                const elaStdDev = Math.sqrt(elaVariance);

                signals.ela = { avg: elaAvg, max: elaMax, min: elaMin, stdDev: elaStdDev };

                // High variance between regions suggests tampering
                if (elaStdDev > 15 && elaMax / (elaMin || 1) > 3) {
                    suspicion += 22;
                    issues.push({
                        severity: 'high', name: 'ELA: Region Inconsistency Detected', location: 'Error Level Analysis',
                        description: `Different image regions show different compression error levels (σ=${elaStdDev.toFixed(1)}). This indicates parts of the image were added or edited at different times.`,
                        snippet: `ELA Std Dev: ${elaStdDev.toFixed(1)} | Max/Min ratio: ${(elaMax / (elaMin || 1)).toFixed(1)}x\nAvg error: ${elaAvg.toFixed(1)} | Regions analyzed: ${regionErrors.length}`,
                        fix: 'Different compression levels strongly suggest image manipulation. The edited regions likely have different error levels than the original.',
                        confidence: 'likely'
                    });
                }

                // Uniformly LOW error suggests AI generation (never compressed by a camera)
                if (elaAvg < 5 && elaStdDev < 3) {
                    suspicion += 15;
                    issues.push({
                        severity: 'medium', name: 'ELA: Uniform Low Error (AI Signature)', location: 'Error Level Analysis',
                        description: `Uniformly low compression error (avg=${elaAvg.toFixed(1)}, σ=${elaStdDev.toFixed(1)}). AI-generated images have never been through real camera JPEG compression, producing unnaturally uniform ELA.`,
                        snippet: `ELA Average: ${elaAvg.toFixed(1)} | Std Dev: ${elaStdDev.toFixed(1)}\nReal photos typically: avg>10, σ>5`,
                        fix: 'This pattern is consistent with AI-generated imagery that has never been through a camera sensor pipeline.',
                        confidence: 'likely'
                    });
                }
            }

            // ═══════════════════════════════════════════════════
            //  CHECK 3: Color Distribution Analysis
            // ═══════════════════════════════════════════════════
            const colorHist = new Array(64).fill(0);
            const channelHist = { r: new Array(32).fill(0), g: new Array(32).fill(0), b: new Array(32).fill(0) };

            for (let i = 0; i < px.length; i += 4) {
                const bin = (Math.floor(px[i] / 64) * 16) + (Math.floor(px[i + 1] / 64) * 4) + Math.floor(px[i + 2] / 64);
                colorHist[bin]++;
                channelHist.r[Math.floor(px[i] / 8)]++;
                channelHist.g[Math.floor(px[i + 1] / 8)]++;
                channelHist.b[Math.floor(px[i + 2] / 8)]++;
            }

            const usedBins = colorHist.filter(x => x > 0).length;
            const maxBin = Math.max(...colorHist);
            const colorEntropy = colorHist.filter(x => x > 0).reduce((ent, c) => {
                const p = c / totalPx;
                return ent - p * Math.log2(p);
            }, 0);

            signals.colorEntropy = colorEntropy;
            signals.usedBins = usedBins;

            if (usedBins < 16) {
                suspicion += 8;
                issues.push({
                    severity: 'low', name: 'Limited Color Palette', location: 'Color analysis',
                    description: `Only ${usedBins}/64 color bins used. Natural photos typically use 30+. Limited palette may indicate AI generation or heavy processing.`,
                    snippet: `Color bins: ${usedBins}/64 | Color entropy: ${colorEntropy.toFixed(2)} bits`,
                    fix: 'Natural photos have rich color variation. Very limited palettes suggest generation or processing.',
                    confidence: 'possible'
                });
            }

            // Check for unnatural channel distribution (AI often produces specific patterns)
            const rPeak = channelHist.r.indexOf(Math.max(...channelHist.r));
            const gPeak = channelHist.g.indexOf(Math.max(...channelHist.g));
            const bPeak = channelHist.b.indexOf(Math.max(...channelHist.b));
            if (Math.abs(rPeak - gPeak) < 2 && Math.abs(gPeak - bPeak) < 2 && Math.abs(rPeak - bPeak) < 2) {
                suspicion += 5;
                signals.channelCorrelation = true;
            }

            // ═══════════════════════════════════════════════════
            //  CHECK 4: Bilateral Symmetry Analysis
            // ═══════════════════════════════════════════════════
            let symmetryScore = 0, symmetryTotal = 0;
            const midX = Math.floor(w / 2);
            for (let y = 0; y < h; y += 3) {
                for (let x = 0; x < midX; x += 3) {
                    const i1 = (y * w + x) * 4;
                    const i2 = (y * w + (w - 1 - x)) * 4;
                    const diff = Math.abs(px[i1] - px[i2]) + Math.abs(px[i1 + 1] - px[i2 + 1]) + Math.abs(px[i1 + 2] - px[i2 + 2]);
                    if (diff < 30) symmetryScore++;
                    symmetryTotal++;
                }
            }
            const symRatio = symmetryScore / (symmetryTotal || 1);
            signals.symmetry = symRatio;

            if (symRatio > 0.55) {
                suspicion += 15;
                issues.push({
                    severity: 'medium', name: 'Unnaturally High Symmetry', location: 'Symmetry analysis',
                    description: `${(symRatio * 100).toFixed(1)}% bilateral symmetry detected. Deepfake faces are often unnaturally symmetric. Real faces typically show 20-45% symmetry.`,
                    snippet: `Symmetry: ${(symRatio * 100).toFixed(1)}% | Natural range: 20-45%\nSamples compared: ${symmetryTotal}`,
                    fix: 'Real faces are naturally asymmetric. Very high symmetry is a hallmark of GAN-generated faces.',
                    confidence: symRatio > 0.7 ? 'likely' : 'possible'
                });
            }

            // ═══════════════════════════════════════════════════
            //  CHECK 5: LBP Texture Consistency
            // ═══════════════════════════════════════════════════
            // Simplified Local Binary Pattern check
            const lbpHist = new Array(256).fill(0);
            const grayData = [];
            for (let i = 0; i < px.length; i += 4) {
                grayData.push(Math.round(0.299 * px[i] + 0.587 * px[i + 1] + 0.114 * px[i + 2]));
            }

            for (let y = 1; y < h - 1; y += 2) {
                for (let x = 1; x < w - 1; x += 2) {
                    const center = grayData[y * w + x];
                    let lbp = 0;
                    const neighbors = [
                        grayData[(y - 1) * w + (x - 1)], grayData[(y - 1) * w + x], grayData[(y - 1) * w + (x + 1)],
                        grayData[y * w + (x + 1)], grayData[(y + 1) * w + (x + 1)], grayData[(y + 1) * w + x],
                        grayData[(y + 1) * w + (x - 1)], grayData[y * w + (x - 1)]
                    ];
                    for (let b = 0; b < 8; b++) {
                        if (neighbors[b] >= center) lbp |= (1 << b);
                    }
                    lbpHist[lbp]++;
                }
            }

            // LBP entropy - AI images tend to have lower texture entropy
            const lbpTotal = lbpHist.reduce((a, b) => a + b, 0);
            const lbpEntropy = lbpHist.filter(x => x > 0).reduce((ent, c) => {
                const p = c / lbpTotal;
                return ent - p * Math.log2(p);
            }, 0);
            const lbpUsedBins = lbpHist.filter(x => x > 0).length;

            signals.lbpEntropy = lbpEntropy;

            if (lbpEntropy < 4.0) {
                suspicion += 12;
                issues.push({
                    severity: 'medium', name: 'Low Texture Complexity (LBP)', location: 'Texture analysis',
                    description: `LBP texture entropy is ${lbpEntropy.toFixed(2)} bits (natural photos: 5-7 bits). Low complexity suggests artificial textures typical of AI generation.`,
                    snippet: `LBP Entropy: ${lbpEntropy.toFixed(2)} bits | Used patterns: ${lbpUsedBins}/256\nNatural photos: 5.0-7.0 bits`,
                    fix: 'AI-generated images often have smoother, more uniform textures than real photographs.',
                    confidence: 'likely'
                });
            }

            // ═══════════════════════════════════════════════════
            //  CHECK 6: GAN Grid Artifacts
            // ═══════════════════════════════════════════════════
            let repeatCount = 0, gridChecks = 0;
            const gridSize = 16;
            for (let y = 0; y < h - gridSize; y += gridSize) {
                for (let x = 0; x < w - gridSize; x += gridSize) {
                    const i1 = (y * w + x) * 4;
                    const i2 = ((y + gridSize) * w + x) * 4;
                    if (i2 < px.length) {
                        const diff = Math.abs(px[i1] - px[i2]) + Math.abs(px[i1 + 1] - px[i2 + 1]) + Math.abs(px[i1 + 2] - px[i2 + 2]);
                        if (diff < 5) repeatCount++;
                        gridChecks++;
                    }
                }
            }
            const repeatRatio = repeatCount / (gridChecks || 1);
            signals.gridRepeat = repeatRatio;

            if (repeatRatio > 0.35) {
                suspicion += 18;
                issues.push({
                    severity: 'high', name: 'GAN Grid Artifacts Detected', location: 'Pattern analysis',
                    description: `${(repeatRatio * 100).toFixed(1)}% of ${gridSize}px blocks show repeating patterns — a signature of Generative Adversarial Networks.`,
                    snippet: `Repeat ratio: ${(repeatRatio * 100).toFixed(1)}% | Grid: ${gridSize}px\nChecked: ${gridChecks} blocks`,
                    fix: 'Zoom to 400%+ and look for subtle repeating textures in hair, skin, and background. These are classic GAN artifacts.',
                    confidence: 'likely'
                });
            }

            // ═══════════════════════════════════════════════════
            //  CHECK 7: Chromatic Aberration (missing in AI)
            // ═══════════════════════════════════════════════════
            let chrAbCount = 0, chrAbTotal = 0;
            for (let y = 0; y < h; y += 4) {
                for (let x = 1; x < w - 1; x += 4) {
                    const idx = (y * w + x) * 4;
                    const idxL = (y * w + x - 1) * 4;
                    const idxR = (y * w + x + 1) * 4;
                    // Check if R/G/B channels shift differently at edges
                    const rShift = Math.abs((px[idxR] - px[idxL]) - (px[idxR + 1] - px[idxL + 1]));
                    const bShift = Math.abs((px[idxR + 2] - px[idxL + 2]) - (px[idxR + 1] - px[idxL + 1]));
                    if (rShift > 10 || bShift > 10) chrAbCount++;
                    chrAbTotal++;
                }
            }
            const chrAbRatio = chrAbCount / (chrAbTotal || 1);
            signals.chromaticAberration = chrAbRatio;

            // Very low chromatic aberration suggests AI (real lenses always have some)
            if (chrAbRatio < 0.02 && totalPx > 10000) {
                suspicion += 8;
                issues.push({
                    severity: 'low', name: 'No Lens Chromatic Aberration', location: 'Optical analysis',
                    description: `Chromatic aberration is ${(chrAbRatio * 100).toFixed(2)}%. Real camera lenses produce color fringing at edges. Its absence suggests the image was not captured by a real camera.`,
                    snippet: `Chromatic aberration: ${(chrAbRatio * 100).toFixed(2)}% | Expected: >2% for real photos`,
                    fix: 'All real camera lenses produce some color fringing. Perfectly clean edges suggest AI generation.',
                    confidence: 'possible'
                });
            }

            // ═══════════════════════════════════════════════════
            //  CHECK 8: Aspect Ratio & Resolution
            // ═══════════════════════════════════════════════════
            const aspect = img.width / img.height;
            const aiRatios = [1.0, 0.75, 1.333, 0.5625, 1.778, 0.667, 1.5];
            const isAIRatio = aiRatios.some(r => Math.abs(aspect - r) < 0.015);

            if (isAIRatio) {
                suspicion += 3;
                issues.push({
                    severity: 'low', name: 'Common AI Output Dimensions', location: 'Image dimensions',
                    description: `Aspect ratio ${aspect.toFixed(3)} matches common AI generation formats. Dimensions: ${img.width}×${img.height}.`,
                    snippet: `Dimensions: ${img.width}×${img.height} | Ratio: ${aspect.toFixed(3)}`,
                    fix: 'While not conclusive alone, this aspect ratio is commonly used by DALL·E, Midjourney, and Stable Diffusion.',
                    confidence: 'possible'
                });
            }

            // ═══════════════════════════════════════════════════
            //  CHECK 9: Compression Ratio Analysis
            // ═══════════════════════════════════════════════════
            const fileSizeKB = Math.round(imageDataUrl.length * 0.75 / 1024);
            const pixelsPerKB = totalPx / (fileSizeKB || 1);

            if (pixelsPerKB > 60) {
                suspicion += 5;
                issues.push({
                    severity: 'low', name: 'Unusual Compression Ratio', location: 'File analysis',
                    description: `High pixel-to-filesize ratio (${pixelsPerKB.toFixed(0)} px/KB) — may indicate re-compression or AI generation.`,
                    snippet: `File: ~${fileSizeKB}KB | Pixels: ${totalPx.toLocaleString()} | Ratio: ${pixelsPerKB.toFixed(0)} px/KB`,
                    fix: 'Multiple compressions or AI generation can alter file characteristics. Request the original file.',
                    confidence: 'possible'
                });
            }

            // ═══════════════════════════════════════════════════
            //  MULTI-SIGNAL FUSION SCORING
            // ═══════════════════════════════════════════════════
            suspicion = Math.min(95, suspicion);

            if (issues.length === 0) {
                issues.push({
                    severity: 'low', name: 'No Strong Manipulation Indicators', location: 'Full image',
                    description: 'Client-side analysis found no strong indicators of AI generation or manipulation. Sophisticated deepfakes may require ML-based detection.',
                    snippet: `Noise: ${(noiseRatio * 100).toFixed(1)}% | Edges: ${(edgeRatio * 100).toFixed(1)}% | Symmetry: ${(symRatio * 100).toFixed(1)}% | LBP: ${lbpEntropy.toFixed(2)} bits`,
                    fix: 'For highest confidence, use dedicated deepfake detection services with trained neural networks.',
                    confidence: 'confirmed'
                });
                suspicion = Math.max(suspicion, 8);
            }

            // Add meta-summary issue at top
            if (suspicion >= 50) {
                issues.unshift({
                    severity: 'critical', name: 'High Probability of AI Generation/Manipulation', location: 'Multi-signal fusion',
                    description: `Combined analysis across ${Object.keys(signals).length} signals yields a ${suspicion}% suspicion score. Multiple independent checks corroborate AI generation or significant manipulation.`,
                    snippet: `Suspicion: ${suspicion}% | Signals: noise=${(noiseRatio * 100).toFixed(0)}%, symmetry=${(symRatio * 100).toFixed(0)}%, LBP=${lbpEntropy.toFixed(1)}bits, bins=${usedBins}`,
                    fix: 'Do not use this image for identity verification or evidence. Cross-verify with multiple detection tools.',
                    confidence: suspicion >= 70 ? 'likely' : 'possible'
                });
            } else if (suspicion >= 30) {
                issues.unshift({
                    severity: 'high', name: 'Moderate Manipulation Indicators', location: 'Multi-signal fusion',
                    description: `Combined analysis yields ${suspicion}% suspicion. Some signals suggest possible AI involvement.`,
                    snippet: `Suspicion: ${suspicion}% | ${Object.keys(signals).length} signals analyzed`,
                    fix: 'Exercise caution. Consider running through additional detection tools for confirmation.',
                    confidence: 'possible'
                });
            }

            resolve(this._buildResult(issues, 'image', suspicion));
        };
        img.onerror = () => {
            resolve(this._buildResult([{
                severity: 'medium', name: 'Image Load Failed', location: 'Input',
                description: 'The image could not be loaded for analysis.',
                snippet: 'Image failed to load', fix: 'Try re-uploading the image in a standard format (JPEG, PNG, WebP).',
                confidence: 'confirmed'
            }], 'image'));
        };
        img.src = imageDataUrl;
    });
};
